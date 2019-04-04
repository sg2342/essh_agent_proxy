-module(essh_agent_proxy).

-export([main/1]).

main([]) -> fail("~nUsage: ~s CertFile1 ... CertFile~n",
		 [filename:basename(escript:script_name())]);
main(CertPathS) ->
    logger:set_primary_config(level, notice),
    Certs = lists:ukeysort(2, lists:filtermap(fun read_cert/1, CertPathS)),
	main1(os:getenv("SSH_AUTH_SOCK"), Certs).

main1(false, _) -> fail("SSH_AUTH_SOCK not set", []);
main1(_, []) -> fail("No certificates", []);
main1(SshAuthSock, Certs) ->
    listen("/tmp/essh_agent_proxy." ++ os:getpid(), SshAuthSock, Certs).


fail(Msg, Args) ->
    logger:critical(Msg, Args),
    timer:sleep(1), % give logger_std_h a chance
    halt(1).


read_cert(Path) -> read_cert1(file:read_file(Path), Path).

read_cert1({error, Error}, Path) ->
    logger:error("could not read certificate ~p :~p", [Path, Error]), false;
read_cert1({ok, Bin}, Path) ->
   try
       [_Type, BlobBase64, _Comment] =
	   binary:split(Bin, [<<" ">>, <<"\t">>, <<"\n">>], [global, trim]),
       CertBlob = base64:decode(BlobBase64),
       KBlob = k_of_blob(CertBlob),
       {true, {KBlob, CertBlob, list_to_binary("GRAFT: "++ Path)}}
   catch _C:_E ->
	   logger:error("could not decode certificate ~p", [Path]), false
   end.


listen(ProxySock, SshAuthSock, Certs) ->
    logger:notice("started grafting proxy (for ssh-agent ~s)~n"
		  "\tCertificates:~p~n\tProxy Socket: ~s~n",
		  [SshAuthSock, [Comment || {_,_,Comment} <- Certs], ProxySock]),
    MaybeLSock = gen_tcp:listen(0, [{ifaddr, {local, ProxySock}}, local, binary,
				    {packet, 4}]),
    listen1(MaybeLSock, SshAuthSock, Certs).

listen1({error, _} = Error, _, _) -> fail("listen: ~p", [Error]);
listen1({ok, Sock}, SshAuthSock, Certs) -> listen2(Sock, SshAuthSock, Certs).

listen2(Sock, SshAuthSock, Certs)->
    Self = self(),
    {Pid, Ref} =
	spawn_opt(
	  fun() -> accepted(gen_tcp:accept(Sock), Self, SshAuthSock, Certs) end,
	  [monitor]),
    receive
	{'DOWN', Ref, process, Reason} ->
	    logger:error("Crash: ~p", [Reason]),
	    listen2(Sock, SshAuthSock, Certs);
 	{Pid, ok} ->
	    erlang:demonitor(Ref, [flush]),
	    listen2(Sock, SshAuthSock, Certs);
	{Pid, Error} -> fail("connect failed: ~p", [Error])
    end.


accepted({ok, C}, Caller, SshAuthSock, Certs) ->
    MaybeSock = gen_tcp:connect({local, SshAuthSock}, 0,
				[{active, once}, binary, {packet, 4}]),
    accepted1(MaybeSock, C, Caller, Certs).

accepted1({error, _} = Error, C, Caller, _Certs) ->
    Caller ! {self(), Error},
    gen_tcp:close(C);
accepted1({ok, S}, C, Caller, Certs) ->
    Caller ! {self(), ok},
    proxy({C, S}, Certs).


-define(BYTE(X),          (X):8/unsigned-big-integer).
-define(UINT32(X),        (X):32/unsigned-big-integer).
-define(BINARY(X,Len),    ?UINT32(Len), X:Len/binary ).
-define(MPINT(I,Len),     ?UINT32(Len), I:Len/big-signed-integer-unit:8 ).

-define(SSH2_AGENT_IDENTITIES_ANSWER,           12).


proxy({C, S}, Certs) ->
    receive
	{tcp, S, <<?BYTE(?SSH2_AGENT_IDENTITIES_ANSWER),
		   Len:32, Items/binary>>} when Len > 0 ->
	    Ids = dec_identities(Items),
	    Graft = [{Blob, Comment} || {K, Blob, Comment} <- Certs,
					lists:keymember(K, 1, Ids),
					not lists:keymember(Blob, 1, Ids)],
	    gen_tcp:send(C, enc_resp(Graft ++ Ids)),
	    inet:setopts(S, [{active, once}]),
	    proxy({C, S}, Certs);
	{tcp, S, Resp} ->
	    gen_tcp:send(C, Resp),
	    inet:setopts(S, [{active,once}]),
	    proxy({C, S}, Certs);
	{tcp, C, Req} ->
	    gen_tcp:send(S, Req),
	    inet:setopts(C, [{active, once}]),
	    proxy({C, S}, Certs);
	{tcp_closed, _C_or_S} -> gen_tcp:close(C), gen_tcp:close(S);
	{tcp_error, _C_or_S, _Error} -> gen_tcp:close(S), gen_tcp:close(C)
    end.


enc_resp(L) ->
    erlang:iolist_to_binary(
      [<<?SSH2_AGENT_IDENTITIES_ANSWER, (length(L)):32>>,
       [<<?BINARY(Blob, (byte_size(Blob)))
	 ,?BINARY(Comment, (byte_size(Comment)))>> ||
	   {Blob, Comment} <- L]]).


dec_identities(Items) -> dec_identities(Items, []).

dec_identities(<<>>, Acc) -> lists:reverse(Acc);
dec_identities(<<?BINARY(Blob, _BlobL), ?BINARY(Comment, _CommentL)
		 ,Rest/binary>>, Acc) ->
    dec_identities(Rest, [{Blob, Comment} | Acc]).


% massage a cert blob into the matching public key blob
k_of_blob(<<?BINARY(Type, _TypeLen) ,?BINARY(_Nonce, _NonceLen)
	   ,?MPINT(E, ELen) ,?MPINT(N, NLen)
	   ,_Rest/binary>>)
  when Type == <<"ssh-rsa-cert-v01@openssh.com">> ->
   <<?BINARY(<<"ssh-rsa">>, 7), ?MPINT(E, ELen), ?MPINT(N, NLen)>>;
k_of_blob(<<?BINARY(Type, _TypeLen) ,?BINARY(_Nonce, _NonceLen)
	   ,?BINARY(PubKey, PubKeyLen)
	   ,_Rest/binary>>)
  when Type == <<"ssh-ed25519-cert-v01@openssh.com">> ->
    <<?BINARY(<<"ssh-ed25519">>, 11) ,?BINARY(PubKey, PubKeyLen)>>;
k_of_blob(<<?BINARY(Type, _TypeLen) ,?BINARY(_Nonce, _NonceLen)
	   ,?MPINT(P, PLen) ,?MPINT(Q, QLen)
	   ,?MPINT(G, GLen) ,?MPINT(Y, YLen)
	   ,_Rest/binary>>)
  when Type == <<"ssh-dss-cert-v01@openssh.com">> ->
    <<?BINARY(<<"ssh-dss">>, 7),?MPINT(P, PLen) ,?MPINT(Q, QLen)
     ,?MPINT(G, GLen) ,?MPINT(Y, YLen)>>;
k_of_blob(<<?BINARY(Type, _TypeLen) ,?BINARY(_Nonce, _NonceLen)
	   ,?BINARY(Curve, CurveLen) ,?BINARY(PubKey, PubKeyLen)
	   ,_Rest/binary>>)
  when Type == <<"ecdsa-sha2-nistp384-cert-v01@openssh.com">> ;
       Type == <<"ecdsa-sha2-nistp256-cert-v01@openssh.com">> ;
       Type == <<"ecdsa-sha2-nistp521-cert-v01@openssh.com">> ->
    T = binary:part(Type, {0,19}),
    <<?BINARY(T, 19) ,?BINARY(Curve, CurveLen) ,?BINARY(PubKey, PubKeyLen)>>.
