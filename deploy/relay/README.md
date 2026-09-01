# Parent Approval relay

HTTPS origin phones talk to. Laptops dial outbound WSS. Do not terminate TLS
in the Go container.

Default public URL: `https://parentapprovals.com`

## Railway

Project config is Infrastructure as Code in [`.railway/railway.ts`](../../.railway/railway.ts)
(not deprecated `railway.toml` / `railway.json`). After editing:

```bash
npm install
railway config plan
railway config apply
```

The file owns the `omarchy-parentapproval` service:

1. GitHub source `aphexddb/omarchy-parentapproval` (`main`). The root
   `Dockerfile` is the builder; Railpack/nixpacks is unused.
2. `RELAY_PUBLIC_URL=https://parentapprovals.com` (or your custom domain).
   `PUBLIC_URL` is accepted as an alias. Railway sets `PORT`.
3. Volume `relay-data` at `/data`. VAPID keys live in `/data/vapid.json` and
   must not rotate silently — keep the volume.
4. Custom domain `parentapprovals.com` on port 8080. Railway issues Let's
   Encrypt. Do not run ACME in the container.
5. Single replica in `sfo`. Host connections and live tokens are in memory;
   VAPID, push subscriptions, and tokens also persist as JSON under `/data`.
6. Health check `GET /healthz`. Railway's default restart policy is on failure.

`railway up` still works for a one-off from this directory. Prefer connecting
the GitHub repo and applying the IaC file.

## Local

```bash
make relay
mkdir -p /tmp/parentapproval-data
PORT=8080 RELAY_PUBLIC_URL=http://127.0.0.1:8080 RELAY_DATA=/tmp/parentapproval-data \
  ./bin/omarchy-parentapproval-relay
```

Point a laptop at it:

```bash
parentapproval daemon --dev --relay http://127.0.0.1:8080
```

## Self-host with Caddy

People who change the TLD can run `docker compose` in this directory. Edit
`Caddyfile` and `RELAY_PUBLIC_URL` to the new hostname. Caddy terminates TLS;
the relay still listens on HTTP `:8080` inside the compose network.
