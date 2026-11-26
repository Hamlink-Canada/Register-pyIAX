# IAX repeater registration

This service accepts IAX2 registrations from repeater nodes. It verifies their MD5
challenge responses and publishes accepted registrations to Kafka for the DNS
directory. It listens on UDP port 4569 and supports IPv4 nodes. RSA authentication
is not supported.

You need Docker, a reachable Kafka broker, and credentials for the nodes allowed
to register. The address and UDP port observed by the service are published as the
node's endpoint, so the deployment must preserve the client's source address unless
PROXY protocol v2 is enabled for a trusted UDP proxy.

See the [IAX registrar documentation](docs/README.md) for protocol and authentication details.
The cross-project [operator guide](https://hamlink-canada.github.io/apt-rpt-docs/projects/iax/)
explains how it fits with the other services.

## Prepare node credentials

Create a CSV file containing a generated password for each node:

```csv
node_id,password
1234,YOUR_GENERATED_PASSWORD
```

The file requires the `node_id,password` header. IDs must be numeric and unique;
passwords must be 1–79 printable ASCII characters without whitespace. Generated
32-character base64url passwords are suitable for client configuration. The service
loads and validates the file at startup, so restart it after making changes.
Never commit a real credential file.

The container runs as UID/GID 10001. Set the host file's ownership and permissions
so that this user can read it while access by other users is restricted.

## Run the service

Choose a versioned image from `ghcr.io/hamlink-canada/register-pyiax` when a release
is available. Before an image is published, [build this checkout](#build-an-image)
and use `rpt-iax-register:local`.

This Linux example uses host networking to preserve the client's source address.
With `credentials.csv` in the current directory, replace the broker address below:

```sh
IMAGE=rpt-iax-register:local

docker run -d --name rpt-iax --restart unless-stopped \
  --network host \
  --mount "type=bind,src=$(pwd)/credentials.csv,dst=/run/secrets/credentials.csv,readonly" \
  --env RPT_AUTH__BACKEND=file \
  --env RPT_AUTH__FILE=/run/secrets/credentials.csv \
  --env RPT_KAFKA__BOOTSTRAP=kafka.example.org:9092 \
  --env RPT_KAFKA__TOPIC=rpt.registrations \
  --env RPT_SERVER_ID=iax-1 \
  "$IMAGE"
```

Allow incoming UDP 4569 through the host firewall. Host networking uses the host's
port directly, so another IAX service cannot occupy the same address and port.
Kafka's advertised broker addresses must also be reachable from the container.

You can use another networking arrangement if it preserves the original source
address and UDP port. Verify those values in the resulting registration before
using it for a public endpoint. See [IAX behavior](docs/iax.md) for protocol and
networking details.

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `RPT_HOST` | `0.0.0.0` | Local address to bind. |
| `RPT_PORT` | `4569` | UDP listening port. |
| `RPT_KAFKA__BOOTSTRAP` | `localhost:9092` | Kafka bootstrap address. |
| `RPT_KAFKA__TOPIC` | `rpt.registrations` | Topic shared with the DNS directory. |
| `RPT_SERVER_ID` | `registrar-1` in the image settings | Identifier included in registrations. |
| `RPT_REFRESH` | `60` | Refresh value sent in REGACK, in seconds. |
| `RPT_LIFETIME` | `180` | Registration validity in the DNS directory, in seconds. |
| `RPT_PROXY_PROTOCOL__ENABLED` | `false` | Require PROXY protocol v2 headers on every IAX datagram. |
| `RPT_PROXY_PROTOCOL__TRUSTED_PROXIES` | `[]` | IPv4 CIDRs allowed to send PROXY protocol datagrams. Required when proxy protocol is enabled. |
| `RPT_AUTH__BACKEND` | `file` | Credential source: `file` or `grpc`. |
| `RPT_AUTH__FILE` | `/run/secrets/credentials.csv` in the image settings | Local credential file. |

Dynaconf reads `settings.toml` and optional `.secrets.toml` from the working directory,
then applies `RPT_` environment overrides. Use two underscores for nested settings.
For host-managed files mounted at `/config`, set `RPT_CONFIG_DIR=/config`. Files use
plain TOML without environment sections. Use absolute paths for mounted credentials.

To enable PROXY protocol, configure the trusted proxy addresses in `settings.toml`:

```toml
[proxy_protocol]
enabled = true
trusted_proxies = ["192.0.2.10/32"]
```

Replace the example with the IPv4 CIDRs of the proxy hosts. When enabled, the listener
requires valid PROXY v2 headers on every datagram.

The `grpc` backend retrieves a node's password from a compatible credential service.
IAX challenge-response verification stays in this service. The `Register-Central_Auth`
repository implements the production credential server. The client requires verified
TLS and a service token or client certificate. Successful lookups use a cache of up
to 4096 entries with a 60-second TTL by default. Unexpired credentials remain usable
during an outage; expired credentials and new lookups fail closed. Password rotation can take
up to the cache TTL to become visible. The service never falls back to the CSV file
automatically.

See [authentication and limits](docs/authentication.md) for gRPC, TLS, cache, and
rate-limit settings. Application limits are per process. Use shared network controls
for multiple instances, and allow suitable capacity for nodes behind shared NAT.

## Check a registration

On an Asterisk node, add its ID, generated password, and your registrar's hostname
to the `[general]` section of `iax.conf`:

```ini
[general]
register => 1234:YOUR_GENERATED_PASSWORD@register.example.org
```

See the [AllStarLink IAX registration guide](https://allstarlink.github.io/adv-topics/iaxreg/)
for client setup. `iax2 show registry` in the Asterisk CLI shows its status. After a
successful exchange, check that the DNS directory reports the node's expected public
address and IAX port.

```sh
docker logs --tail 100 rpt-iax
docker restart rpt-iax
docker stop rpt-iax
```

If a node cannot register, check its ID and password, UDP connectivity, authentication
limits, and Kafka connectivity. The registrar sends REGACK only after Kafka confirms
the update. A registration rejection can therefore mean that publication failed as
well as that credentials were rejected.

Challenges expire after 30 seconds and are bound to the peer and node identity.
Retransmissions reuse the transaction's response without publishing duplicate updates.
SIGTERM stops request admission and closes service resources.

## Build an image

From this checkout, with Docker Buildx and Python 3.13+ installed:

```sh
PROTOBUF_REV=$(python3 scripts/dependency.py)
docker buildx build --load \
  --build-context "rpt_protobuf=https://github.com/Hamlink-Canada/rpt_protobuf.git#${PROTOBUF_REV}" \
  --tag rpt-iax-register:local .
```

The build fetches the public protobuf library from its `main` branch.
The image starts `rpt-iax`.

## Development

Use Python 3.13+ and uv. Place this checkout next to `rpt_protobuf`, with the library
on an up-to-date `main` branch. uv installs the sibling library
in editable mode.

```sh
uv sync --locked
make check test build
RPT_AUTH__FILE=examples/credentials.csv uv run --locked rpt-iax
```

The example credentials are for local development only. To build an image using
local library changes, replace the remote context with
`--build-context rpt_protobuf=../rpt_protobuf`. Standard Python installations use
the `main` branch in `pyproject.toml`. CI uses one resolved revision per run; separate
builds can use newer library code. Refresh lockfiles when dependency metadata changes. Keep schemas and generated bindings in the
shared library.

CI checks Python 3.13 and 3.14 and is configured for Linux AMD64 and ARM64 image
builds and runtime imports. Published GitHub releases with `vMAJOR.MINOR.PATCH` tags publish versioned images
and commit-SHA
tags; only stable releases update `latest`. Pull requests never publish images.
There is no PyPI release.

Images are published only after the release workflow passes its tests and container
checks. Publishing a GitHub prerelease (for example, `v1.0.1-rc.1`) publishes its
version and commit-SHA image tags without updating `latest`. Pushing a tag alone
does not publish an image. Registry authentication uses the built-in `GITHUB_TOKEN`.

## License

[AGPL-3.0-or-later](LICENSE).
