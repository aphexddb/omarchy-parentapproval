# Parent Approval relay

HTTPS origin phones talk to. Laptops dial outbound WSS. Do not terminate TLS
in the Go container.

Default public URL: `https://parentapprovals.com`

## Railway

1. Create a service from this repo. The root `Dockerfile` is enough; nixpacks is unused.
2. `railway up` (or connect the GitHub repo).
3. Set `RELAY_PUBLIC_URL=https://parentapprovals.com` (or your custom domain).
   `PUBLIC_URL` is accepted as an alias. Railway sets `PORT`.
4. Attach a volume at `/data`. VAPID keys live in `/data/vapid.json` and must
   not rotate silently — keep the volume.
5. Add custom domain `parentapprovals.com`. Railway issues Let's Encrypt.
   Do not run ACME in the container.
6. Single replica. Host connections and live tokens are in memory; VAPID,
   push subscriptions, and tokens also persist as JSON under `/data`.

Health check: `GET /healthz`.

## Local

```bash
make relay
mkdir -p /tmp/parentapproval-data
PORT=8080 RELAY_PUBLIC_URL=http://127.0.0.1:8080 RELAY_DATA=/tmp/parentapproval-data \
  ./bin/omarchy-parentapproval-relay
```

Point a laptop at it:

```bash
omarchy-parentapproval daemon --dev --relay http://127.0.0.1:8080
```

## Self-host with Caddy

People who change the TLD can run `docker compose` in this directory. Edit
`Caddyfile` and `RELAY_PUBLIC_URL` to the new hostname. Caddy terminates TLS;
the relay still listens on HTTP `:8080` inside the compose network.
