# Deploying to DigitalOcean App Platform

**This is how the reference provider (www.giveme.my) runs.** App Platform
builds the repo's [`Dockerfile`](../Dockerfile) and deploys automatically on
every push to the tracked branch.

> **Merging to the tracked branch ships to production.** The live app is
> configured with `branch: main` and `deploy_on_push: true`, so a merged pull
> request is a release — there is no promotion step and no approval gate.
> DigitalOcean also builds from GitHub independently of GitHub Actions, so a
> red CI run does not stop a deploy; required status checks on the branch are
> what make CI meaningful.
>
> Blast radius is bounded: App Platform keeps the current deployment serving
> until the new one passes its `/healthz` check, so a container that fails to
> boot leaves production up rather than taking it down.

If you would rather deploy on hardware you control, with manual approval and
an explicit rollback path, see [UBUNTU_DEPLOY.md](UBUNTU_DEPLOY.md).

**The checked-in [`.do/app.yaml`](../.do/app.yaml) is a bootstrap template,
not a mirror of the live app.** Its secrets are `REPLACE_WITH` placeholders,
so applying it over a running app overwrites the real `DJANGO_SECRET_KEY` and
signing keys. To change a live app, pull its spec, edit that, and apply it
back:

```bash
doctl apps spec get <app-id> > /tmp/live.yaml
$EDITOR /tmp/live.yaml
doctl apps update <app-id> --spec /tmp/live.yaml
```

The live spec is also the only reliable answer to "what branch does this
deploy from?" — read it there, or in the DO console under
App → Settings → App Spec, rather than trusting this repository.

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

### 1. Create a gitignored local spec

Copy the checked-in template, restrict it, then replace every
`REPLACE_WITH_...` sentinel in the local copy with the real value:

```bash
cp .do/app.yaml .do/app.local.yaml
chmod 600 .do/app.local.yaml
```

| Field | What to paste |
| --- | --- |
| `PKH` | The PKH derived from your `payment.vkey` |
| `DJANGO_SECRET_KEY` | The 50-char random string from above |
| `SKEY_CONTENTS` | The bare `cborHex` string from `payment.skey` (for example, `5820...`), injected as a DO secret |
| `VKEY_CONTENTS` | The bare `cborHex` string from `payment.vkey`, injected as a DO secret |
| `PREPROD_TXID`, `PREPROD_TXIDX` | The collateral UTxO you've funded on preprod |
| `MAINNET_TXID`, `MAINNET_TXIDX` | The collateral UTxO you've funded on mainnet |
| `ALLOWED_HOSTS` | Keep `.ondigitalocean.app` only for the first health check; after step 2, replace it with the exact DO-issued hostname plus your custom domain, if any |

Do not paste an unquoted full JSON key object into the spec: YAML parses
it as a mapping instead of a string. The entrypoint intentionally accepts the
bare `cborHex` form so the checked-in spec remains unambiguous. If you inject
secrets through another mechanism, a correctly quoted full JSON string is
also accepted.

The `github.repo` field assumes
`logical-mechanism/Collateral-Provider`. If you're deploying a fork,
update it.

> ⚠️ The `value:` next to a `type: SECRET` env var goes into DO's
> encrypted store the moment you submit the spec. It is **not**
> retrievable afterwards — only updatable. `.do/app.local.yaml` is ignored by
> both Git and the Docker build context, but it is still a plaintext local
> secret file: keep mode 0600, protect backups, and never force-add it.

### 2. Create the app

```bash
doctl apps create --spec .do/app.local.yaml
```

App Platform will:
1. Clone the repo at the tracked branch (`main` on the live app).
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
in `.do/app.local.yaml` to include it (without the scheme) and remove the
temporary `.ondigitalocean.app` wildcard, then apply the
updated spec:

```bash
doctl apps update <app-id> --spec .do/app.local.yaml
```

### 3. Verify the deploy

```bash
# Healthcheck (note: the app's hostname, not your custom domain)
curl -fsS https://<app-hostname>/healthz

# Real signing request (preprod, with a real preprod tx CBOR)
curl -fsS -X POST https://<app-hostname>/preprod/collateral/ \
     -H 'Content-Type: application/json' \
     -d '{"tx":"<hex-tx-cbor>"}'
```

If `/healthz` returns 503, the signing keys probably didn't materialize
correctly. `doctl apps logs <app-id> --type run` will show the boot-time
error from `ApiConfig.ready()`.

### 4. Optional: custom domain

In the App Platform web console:
1. Add your domain under **Settings → Domains**.
2. Update your DNS to the `CNAME` DO provides.
3. DO provisions a free Let's Encrypt cert.
4. Add the domain to `ALLOWED_HOSTS` using the pull-edit-apply flow under
   [Updating env vars](#updating-env-vars). Never include a bare `*` — one
   wildcard voids every other entry in the list.

## Day-2 operations

### Updating env vars

**Always edit the live spec, never your local copy.** `.do/app.local.yaml` is
a snapshot taken when you created the app, and a running app drifts from it —
this one did, on the deployed branch, the throttle rate, and `ALLOWED_HOSTS`.
Applying a stale local file silently reverts every change made since.

```bash
doctl apps spec get <app-id> > /tmp/live.yaml
$EDITOR /tmp/live.yaml
doctl apps update <app-id> --spec /tmp/live.yaml
```

This triggers a rolling redeploy with the new values. Existing requests
finish on the old container before traffic shifts.

Values marked SECRET come back from `spec get` as encrypted `EV[1:...]`
blobs. Leave them untouched and they re-apply unchanged; replace one with
plaintext to rotate it.

### Rotating the signing keys

1. Generate a new key pair on a host that's not the App Platform
   instance.
2. Fund a new collateral UTxO under the new PKH.
3. Update `SKEY_CONTENTS`, `VKEY_CONTENTS`, `PKH`, and
   `PREPROD_TXID`/`MAINNET_TXID` together, in the live spec pulled via
   `doctl apps spec get` — all in one edit, so they apply atomically.
4. `doctl apps update <app-id> --spec /tmp/live.yaml`. App Platform rolls the
   new keys in; the old container drains. A brief race window where the
   advertised collateral UTxO doesn't match the advertised PKH is
   unavoidable — schedule rotation off-peak.

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

**App Platform does not support volumes.** Its filesystem is ephemeral and is
wiped on every deploy and container replacement, and the app spec has no mount
or volume field — DigitalOcean documents external storage (Spaces, a managed
database) as the only durable option. So the hot-reload property these files
have elsewhere does not exist here:

- `known.hosts.json` is baked into the image. Editing it means committing and
  merging to the deployed branch, which is itself a release.
- `bans.json` is **never present at all**. It is gitignored and excluded by
  `.dockerignore`, so `BANS_PATH` points at a file that does not exist and the
  ban list is permanently empty. If you need bans on App Platform, either bake
  a `bans.json` into the image by removing it from `.dockerignore`, or run the
  self-hosted deployment where the operator-editable file works as designed.

### Scraping `/metrics`

Off by default. To turn on, add to `.do/app.local.yaml`:

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
    bans.json                          NOT PRESENT (gitignored + dockerignored)
    known.hosts.json (parent dir)      baked into image; edit = commit + deploy
/run/keys/                             ephemeral writable layer, populated by entrypoint
  payment.skey                         from $SKEY_CONTENTS
  payment.vkey                         from $VKEY_CONTENTS
```

Mount `/run/keys` as tmpfs if your container platform supports it and you need
the materialized key files to be memory-backed. The default image guarantees
only that they are absent from image layers and discarded with the container.
