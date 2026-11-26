# Authentication and abuse controls

Choose `RPT_AUTH__BACKEND=file` or `grpc`. Local-file mode requires a CSV with an
explicit `node_id,password` header. A numeric ID may appear only once. Rows and
passwords are validated at startup; restart to reload. Passwords are 1–79 printable
ASCII characters without whitespace. Use system-generated base64url credentials
for AllStarLink configuration compatibility. `examples/credentials.csv` is illustrative;
mount a real file at `/run/secrets/credentials.csv` readable by UID 10001.

For gRPC configure `RPT_AUTH__BACKEND=grpc`, `RPT_GRPC__TARGET`, and a service token
(`RPT_GRPC__TOKEN`) or both `RPT_GRPC__CLIENT_CERT` and `RPT_GRPC__CLIENT_KEY`.
`RPT_GRPC__CA` selects a custom CA; otherwise system roots are used. Server hostname
verification stays enabled. Development-only insecure transport requires both
`RPT_ENVIRONMENT=development` and `RPT_GRPC__INSECURE=true`. The Register-Central_Auth repository implements the credential server. It authenticates
registrar identities and authorizes the scope of each lookup; TLS alone does not grant
lookup permission.

Successful credential lookups use a thread-safe per-process LRU cache, default 4096
entries and 60-second TTL (`AUTH.CACHE_SIZE`, `AUTH.CACHE_TTL`). Unexpired credentials
remain usable during outages; misses and expired entries fail closed. No negative
or authentication-success caching, stale extension, or provider fallback. Invalid
proofs do not evict credentials or force lookups. Every password or challenge response
is verified. Rotation/revocation takes effect within the cache TTL. Fixed lock stripes
deduplicate simultaneous lookups; wait times and RPC calls are bounded. Default RPC
deadline is 2 seconds and lookup concurrency is 16 per process. Credentials and raw
authentication packets/bodies are never logged by this service.

`RPT_LIMITS__...` configures bounded per-process token buckets:

| Setting | Sustained rate/minute | Burst |
| --- | ---: | ---: |
| GLOBAL_RATE / GLOBAL_BURST | 60000 | 2000 |
| SOURCE_RATE / SOURCE_BURST | 600 | 120 |
| FAIL_IP_RATE / FAIL_IP_BURST | 30 | 30 |
| FAIL_PAIR_RATE / FAIL_PAIR_BURST | 5 | 5 |
| REFRESH_RATE / REFRESH_BURST | 6 | 3 |

These are initial operational defaults, not universal capacity guarantees. Sources
behind shared NAT need appropriate burst capacity. Failure budgets are distinct
from successful refresh budgets. A malicious source cannot trigger a global node
lockout. Limits and cached state are capped at 16384 keys; new keys are denied when
capacity is exhausted. Workers default to 32; IAX admits traffic before allocating
threads. Challenge state defaults to 4096 transactions with a 30-second verification
window. Malformed input is rejected before credential lookup. Failures are generic.
Internal counters track accepted/failed/throttled events without secret values.

All limits and caches are per process. Multiple Gunicorn workers or replicas multiply
those budgets. Put shared limits at the ingress/firewall for deployment-wide control
and monitoring, especially for distributed attacks and spoofed UDP. No Redis dependency
is introduced here. Plain file credentials and gRPC-retrieved credentials remain
sensitive in memory and must not be exposed in debug dumps or observability payloads.

Application authentication and publisher implementations are intentionally local to
each registrar. Identical provider/configuration/control modules are covered by the
same contract tests; the shared protobuf library remains schema-only. Database and
dummy authentication backends were removed; future database providers can implement
the same `get(node_id)` interface.
