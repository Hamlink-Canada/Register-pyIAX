# IAX registration behavior

The registrar supports IAX2 MD5 registration, PING/PONG, LAGRQ/LAGRP, and the existing
INFO discovery response. RSA is explicitly rejected. Challenge state is bound to
peer IP, peer UDP port, client/server call numbers, and node identity. Challenges
come from the cryptographic random generator, expire after 30 seconds, and are
consumed after verification. MD5 responses are checked with constant-time comparison.

Exact retransmissions reuse their prior transaction response without re-fetching
credentials or publishing twice. Final ACK releases the completed call so that its
call number can be used for a later registration. Unknown and malformed frames do
not allocate transaction state or trigger credential lookups. Only IPv4 is currently
implemented. The IAX wire REFRESH field remains 60 seconds by default; DNS message
validity is configured separately to permit missed renewals.

SIGTERM stops request admission and closes resources. Preserve the observed source
address and UDP port through container/network ingress: they are the address published
for the node. The service listens on UDP 4569 by default; optional host networking
is a deployment decision rather than a hardcoded Compose requirement.

Protocol reference: https://www.rfc-editor.org/rfc/rfc5456.html
Tests include real UDP exchanges, peer/identity separation, replay, expiry, and final
ACK handling; they do not substitute for a full Asterisk deployment acceptance test.
