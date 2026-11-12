# Repeater Registration

Registration services announce where repeater nodes can be reached. The directory exposes current registrations through DNS.

## Language

**Refresh interval**:
The time a node should wait before renewing its registration.

**Registration lifetime**:
The period for which a registration remains valid, measured from the time it was issued.
_Avoid_: Refresh interval

**Node**:
A repeater endpoint identified by a numeric node ID within its network.

**Registration**:
A time-limited statement of the network address at which a node can be reached.

**Registrar**:
A service that authenticates node registration requests and announces accepted registrations to the directory.

**Registration password**:
A system-generated shared secret used to prove a node's identity during registration.

**Credential service**:
A trusted source of registration passwords for authorized registrars.
