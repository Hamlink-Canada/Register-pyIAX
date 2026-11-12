# IAX registrar documentation

This project accepts IAX2 registration exchanges, verifies node credentials, and
publishes successful registrations to Kafka.

```text
Repeater --IAX2/UDP--> IAX registrar
                       |-- file or Central Auth credential lookup
                       |-- issue and verify peer-bound MD5 challenge
                       +-- publish accepted update --> Kafka
```

IAX challenge-response stays in this service; Central Auth only supplies the
shared password to an authorized registrar. Challenges are short-lived and bound
to the peer and node. Preserve the original client address and UDP port through
the deployment. REGACK follows successful Kafka publication so an accepted client
registration is represented in the directory stream.

The repository [README](../README.md) covers setup and configuration. [IAX
behavior](iax.md) describes protocol and transaction semantics;
[authentication](authentication.md) covers credential providers and request limits.
The [glossary](glossary.md) defines shared terms.
