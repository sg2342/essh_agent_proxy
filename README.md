essh_agent_proxy
=====

Problem
----

the ssh-add(1) manual says

"After loading a private key, ssh-add will try to load corresponding
 certificate information from the filename obtained by appending -cert.pub
 to the name of the private key file."

A certificate in the ssh-agent(1), can be used on any host the ssh-agent has
been forwarded to.

When a pkcs11 provider is added to the ssh-agent(1), certificates can be used
by the ssh client if specified with the `CertificateFile` directive or found at
the default locations (for the key types provided by the added pkcs11 provider).

In order to use a certificate with a pkcs11 provided key on a host to which
the ssh-agent has been forwarded to; the certificate file has to exist on the
host (at the default location or at a location specified with the
`CertificateFile` directive).

Solution (not here!)
----

1. patch ssh-agent(1):
   in `process_add_identity()` of ssh-agent.c, allow to add certificates if a
   matching private key is already present
2. extend ssh-add(1)
   add new option `-X file` which parses the certificate from file and adds it
   to the ssh-agent(1)

Hack (here)
----

essh_agent_proxy:
- proxy SSH_AUTH_SOCK
- intercept SSH2_AGENT_IDENTITIES_ANSWER messages
- add entries for all certificates that match a (key-) identity in the answer


Build
-----

    $ rebar3 escriptize

Run
---

    $ ./essh_agent_proxy
