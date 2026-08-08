# Deploying to DigitalOcean App Platform

This is the one-time setup for the App Platform deploy. Once it's wired
up, every push to `main` rebuilds the image and rolls it out — no SSH,
no `systemctl restart`.

For local development setup, see [README.md](../README.md). This file
is operator-facing.

## Prerequisites

- A DigitalOcean account with billing enabled.
- `doctl` installed and authenticated (`doctl auth init`).
- The repo's collateral signing keys (`payment.skey`, `payment.vkey`)
  on your local disk. They will be uploaded to DO's encrypted secret
  store; they will not enter the repo or the container image.
- A 50-character random string for `DJANGO_SECRET_KEY`. Easiest:
  ```bash
  python3 -c 'import secrets; print(secrets.token_urlsafe(50))'
  ```

## One-time setup

### 1. Edit `.do/app.yaml`

Open [.do/app.yaml](../.do/app.yaml) and replace every
`REPLACE_WITH_...` sentinel with the real value:

| Field | What to paste |
| --- | --- |
| `PKH` | The PKH derived from your `payment.vkey` |
| `DJANGO_SECRET_KEY` | The 50-char random string from above |
| `SKEY_CONTENTS` | The bare `cborHex` string from `payment.skey` (for example, `5820...`), injected as a DO secret |
| `VKEY_CONTENTS` | The bare `cborHex` string from `payment.vkey`, injected as a DO secret |
| `PREPROD_TXID`, `PREPROD_TXIDX` | The collateral UTxO you've funded on preprod |
| `MAINNET_TXID`, `MAINNET_TXIDX` | The collateral UTxO you've funded on mainnet |
| `ALLOWED_HOSTS` | After step 2, paste the DO-issued hostname here, plus your custom domain if you have one |

Do not paste an unquoted full JSON key object into `.do/app.yaml`: YAML parses
it as a mapping instead of a string. The entrypoint intentionally accepts the
bare `cborHex` form so the checked-in spec remains unambiguous. If you inject
secrets through another mechanism, a correctly quoted full JSON string is
also accepted.

The `github.repo` field assumes
`logical-mechanism/Collateral-Provider`. If you're deploying a fork,
update it.

> ⚠️ The `value:` next to a `type: SECRET` env var goes into DO's
> encrypted store the moment you submit the spec. It is **not**
> retrievable afterwards — only updatable. Keep your local copy of
> the spec out of git history (the file is tracked but the
> placeholders are sentinels — don't commit a spec with the secrets
> filled in).

### 2. Create the app

```bash
doctl apps create --spec .do/app.yaml
```

App Platform will:
1. Clone the repo at `main`.
2. Build the Docker image from `Dockerfile`.
3. Boot the container, wait for `/healthz` to return 200, then route
   traffic to it.

The first build typically takes 4–6 minutes. Watch progress:

```bash
doctl apps list
doctl apps get <app-id>
doctl apps logs <app-id> --type build --follow
```

Once live, the app gets a hostname like
`collateral-provider-abc12.ondigitalocean.app`. Update `ALLOWED_HOSTS`
in `.do/app.yaml` to include it (without the scheme), then push the
update:

```bash
doctl apps update <app-id> --spec .do/app.yaml
```

### 3. Verify the deploy

```bash
# Healthcheck (note: the app's hostname, not your custom domain)
curl -fsS https://<app-hostname>/healthz

# Real signing request (preprod, with a real preprod tx CBOR)
python3 scripts/py/query.py preprod <hex-tx-cbor>
```

If `/healthz` returns 503, the signing keys probably didn't materialize
correctly. `doctl apps logs <app-id> --type run` will show the boot-time
error from `ApiConfig.ready()`.

### 4. Optional: custom domain

In the App Platform web console:
1. Add your domain under **Settings → Domains**.
2. Update your DNS to the `CNAME` DO provides.
3. DO provisions a free Let's Encrypt cert.
4. Add the domain to `ALLOWED_HOSTS` in `.do/app.yaml` and push the
   spec.

## Day-2 operations

### Updating env vars

Edit `.do/app.yaml`, then:

```bash
doctl apps update <app-id> --spec .do/app.yaml
```

This triggers a rolling redeploy with the new values. Existing requests
finish on the old container before traffic shifts.

### Rotating the signing keys

1. Generate a new key pair on a host that's not the App Platform
   instance.
2. Fund a new collateral UTxO under the new PKH.
3. Update `SKEY_CONTENTS`, `VKEY_CONTENTS`, `PKH`,
   `PREPROD_TXID`/`MAINNET_TXID` in `.do/app.yaml` simultaneously.
4. `doctl apps update --spec`. App Platform rolls the new keys in;
   the old container drains. Brief race window where the listed
   collateral UTxO doesn't match the listed PKH is unavoidable —
   schedule rotation off-peak.

### Rolling back

App Platform retains previous deploys. Roll back via:

```bash
doctl apps list-deployments <app-id>
doctl apps create-deployment <app-id> --force-rebuild=false \
    --rollback-to <previous-deployment-id>
```

Or in the web console: **Activity** → click a previous deploy →
**Redeploy this version**.

### Editing the ban list / known-hosts registry

Two paths, depending on whether you opted into the persistent volume in
`.do/app.yaml`:

- **Default (no volume).** `bans.json` and `known.hosts.json` live
  inside the image. Edit the files in the repo, commit, push to `main`.
  DO rebuilds and rolls out the new content.

- **With volume.** Files live on the mounted `/data/` volume.
  ```bash
  doctl apps console <app-id> -c web
  $ vi /data/bans.json
  $ exit
  ```
  Use an atomic write-temp-then-rename update. The next request detects the
  file's `(mtime_ns, size, inode)` identity and reloads it even if its timestamp
  is equal or older. Invalid JSON/schema updates retain the last valid data;
  no restart is required.

### Scraping `/metrics`

Off by default. To turn on, add to `.do/app.yaml`:

```yaml
- key: METRICS_ENABLED
  value: "True"
- key: METRICS_ALLOW_IPS
  value: 127.0.0.1,::1,<your-scraper-private-ip>
```

The scraper must be on a network App Platform considers "private" to
hit it — typically a same-VPC droplet. From the public internet,
`/metrics` 404s by design.

### Scaling

The current spec runs one `basic-xxs` instance. To scale:

- **Vertically.** Bump `instance_size_slug` to `basic-xs` / `basic-s`.
- **Horizontally.** Increase `instance_count`. ⚠️ The file-based
  cache backend (used by the throttle) is *per-instance* — at
  `instance_count > 1` the per-IP throttle counts independently per
  worker, so the effective rate is `N * COLLATERAL_THROTTLE_RATE`.
  Switch to a Redis-backed cache (`django-redis`, attach a DO Managed
  Redis) before relying on horizontal scaling.

## What's where on the deployed instance

```
/app/                                  image contents owned by root
  collateral_provider/
    manage.py
    .cache/                            file-based throttle cache (writable)
    staticfiles/                       collected by collectstatic at build
    api/
      key/                             EMPTY — keys land at /run/keys/
    bans.json                          baked into image (or /data/bans.json)
    known.hosts.json (parent dir)      baked into image (or /data/known.hosts.json)
/run/keys/                             ephemeral writable layer, populated by entrypoint
  payment.skey                         from $SKEY_CONTENTS
  payment.vkey                         from $VKEY_CONTENTS
```

Mount `/run/keys` as tmpfs if your container platform supports it and you need
the materialized key files to be memory-backed. The default image guarantees
only that they are absent from image layers and discarded with the container.
