# Prompt: DigitalOcean App Platform integration

Paste this into a fresh Claude Code session. The branch `do-app-platform`
is already created and checked out at the tip of `main`; the v1.2.0 work
(modernization, observability, hot-reloadable config, OpenAPI, /healthz,
/metrics, JSON logging) has just merged.

---

## Brief

The Collateral-Provider repo at `/home/logic/Documents/LogicalMechanism/Collateral-Provider`
currently runs on a single droplet with manually-managed gunicorn. Updates
require SSHing in and bouncing the service. We want **push-to-`main` →
DigitalOcean App Platform rebuilds and serves the new version** — no SSH
required.

Work on the existing `do-app-platform` branch (already created from `main`).
At the end, open a PR back to `main`.

## Read these first

- `CLAUDE.md` — repo orientation. The "Operational extras" section
  matters most.
- `CHANGELOG.md` — the just-merged 1.1.0 + 1.2.0 entries explain every
  config knob and endpoint.
- `collateral_provider/sample.env` — every env var the service reads.
- `SECURITY.md` — operator hardening checklist (TLS proxy, ALLOWED_HOSTS,
  TRUSTED_PROXY_IPS, key locations).
- `.github/workflows/ci.yml` — pattern for synthesizing dummy signing
  keys on a fresh runner.
- `collateral_provider/api/apps.py` — startup key validation.

## Hard constraints

These are non-negotiable per the project's design choices:

1. **Signing keys are local-only.** `payment.skey` / `payment.vkey` must
   never enter the repo, the container image, or any Git artifact. They
   are uploaded by the operator to DigitalOcean's encrypted secrets
   (or mounted as a volume) at deploy time. CI uses all-zero dummies;
   prod uses the real ones from DO's secret store.
2. **No user tracking, no audit logging.** Don't add anything that
   persists per-request data tied to a user/IP/tx. Aggregated metrics
   (already in place via `/metrics`) are fine.
3. **No API keys / no per-user auth.** It stays an open anon API.
4. **Single host today, but the deploy shape should not preclude scaling
   later.** File-based `.cache/` is fine for now, but document where it
   would need to move (Redis/Memcached) if scaled out.

## Known gotchas (real things that will bite you)

These came up during the v1.2.0 work and are easy to miss:

1. **`settings.py` sys.exit(1) if `.env` is missing.** DO sets env vars
   at the platform level, not via a file. Either:
   - Make the `.env` file check optional when the env vars it would have
     set are already present, **or**
   - Have the entrypoint synthesize a `.env` from process env vars
     before starting Django.
   The first is cleaner. `django-environ` is happy reading from
   `os.environ` directly when no file is present.

2. **`api/apps.py` `ApiConfig.ready()` validates signing keys at
   startup** and refuses to boot if they're missing. That's a feature in
   prod (loud failure) but be aware: the container won't start if the
   skey/vkey aren't mounted/available before `manage.py runserver` /
   `gunicorn` runs. The check is skipped during `test` /
   `collectstatic` / `makemigrations` (see the `sys.argv` gate).

3. **`bans.json` and `known.hosts.json` are hot-reloadable from disk.**
   On DO App Platform, the container filesystem is ephemeral —
   modifications inside the running container don't survive a restart
   or re-deploy. Three options, pick one and document it:
   - **Bake into image**: include `bans.json` and `known.hosts.json` at
     build time. Edits require a redeploy. Loses the hot-reload property.
   - **Persistent volume**: DO App Platform supports volumes. Mount one
     at `/data/` and set `BANS_PATH=/data/bans.json`,
     `KNOWN_HOSTS_PATH=/data/known.hosts.json`. Operator edits via
     `doctl apps console` or by uploading a new file via the volume.
   - **Fetch at startup from external storage** (e.g. DO Spaces or
     a small admin endpoint). Most flexible, more moving parts.
   Recommendation: persistent volume. `known.hosts.json` already lives
   at the repo root — could ship a default copy in the image and
   override via the volume if present.

4. **`SECRET_KEY`** must be a real value, not committed. Use DO's
   encrypted env var support.

5. **`ALLOWED_HOSTS`** must include the DO-provided hostname
   (`<app>-<hash>.ondigitalocean.app`) plus any custom domain.
   `ALLOWED_HOSTS=` empty → app refuses to start (by design).

6. **`TRUSTED_PROXY_IPS`** — DO's load balancer is the immediate peer.
   Either:
   - Add DO's load-balancer egress IPs to this list, **or**
   - Set it to a wildcard pattern, **or**
   - Leave the default (`127.0.0.1`, `::1`) — XFF won't be trusted, so
     the throttle will key off DO's LB IP for everyone, which means
     **the per-IP throttle becomes a global throttle**. That's bad.
   Look up DO App Platform's documented egress IPs and configure.

7. **Static files.** `STATIC_ROOT = staticfiles/`. The container needs a
   `collectstatic` step at build time AND something to serve those files
   in production. Easiest: add `whitenoise` to `requirements.in` and
   `WhiteNoiseMiddleware` right after `SecurityMiddleware`.

8. **Health probe**. DO supports a custom HTTP health check. Use
   `GET /healthz`, expect 200. (Already implemented and unthrottled.)

9. **TLS** is terminated at DO's edge. `SECURE_PROXY_SSL_HEADER` is
   already set correctly.

10. **JSON logging**: set `LOG_FORMAT=json` so DO's log aggregator
    indexes fields cleanly. Set `LOG_FILE=/dev/null` or similar so the
    rotating file handler doesn't fight the container's stdout — or
    better, swap the file handler for a stream handler in production
    (one more setting to drive from env).

11. **Database**. The current `DATABASES['default']` uses sqlite
    `:memory:`. We have no models, so this is effectively a no-op. DO
    App Platform asks if you want a managed Postgres — say no.

12. **Workers and memory**. Default gunicorn `workers = 2 *
    cpu_count() + 1`. For a $5 droplet–size DO instance, set workers to
    2–3 explicitly. The `.cache` file backend works across workers on
    one host; if multi-host scaling becomes real, switch to Redis
    (deferred per current design).

## Acceptance criteria

You're done when all of these are true:

1. Pushing to `main` triggers a DO App Platform rebuild that completes
   without manual intervention. The new image becomes live and the old
   one is drained.
2. The deployed app responds 200 to `GET /healthz` from a public test.
3. The deployed app accepts a real `POST /preprod/collateral/` and
   returns a witness — using the operator's real signing keys, which
   were uploaded to DO once at setup and are never in Git.
4. The collateral-throttle correctly identifies different client IPs
   (i.e., XFF trust is configured to honor DO's LB header).
5. `/metrics` is reachable from a configured scraper IP and 404s from
   anywhere else.
6. Logs in DO's panel are JSON-shaped and include `request_id` for
   correlation.
7. CI on the `do-app-platform` branch is green (the existing test suite
   plus any new tests you add).

## Suggested deliverables

In rough commit order:

1. **`Dockerfile`** at the repo root. Multi-stage if it makes the image
   smaller; otherwise a single stage is fine. Python 3.12 base.
   Installs `requirements.txt`, runs `collectstatic`, runs gunicorn.
   Handles the case where signing keys are mounted at a non-default
   path via `SKEY_PATH` / `VKEY_PATH`.

2. **`settings.py` change**: stop hard-failing on missing `.env`. If
   `.env` exists, read it; otherwise rely on `os.environ` directly.
   Keep `sys.exit(1)` for missing required vars (PKH, DJANGO_SECRET_KEY,
   ENVIRONMENT, network configs).

3. **`whitenoise` integration** for static-file serving inside the
   container. Add to `requirements.in`, recompile, add the middleware,
   set `STATICFILES_STORAGE` if compressed serving is wanted.

4. **`.do/app.yaml`** (DO App Platform spec). Defines the service:
   build command, run command, health check path, env vars (with
   `value_type: SECRET` for sensitive ones), persistent volume mount
   for `bans.json` + `known.hosts.json` if going that route.

5. **`docs/DEPLOY.md`** (or a section in README) — operator-facing
   one-time setup steps:
   - `doctl apps create --spec .do/app.yaml` (or via web console)
   - Setting required env vars (which ones, where to get values)
   - Uploading signing keys (which method)
   - Pointing the custom domain
   - How to roll back

6. **A small Docker smoke test** — script or CI step that builds the
   image, runs it with synthetic env, curls `/healthz`, asserts 200.
   Something like:
   ```yaml
   - name: Docker smoke test
     run: |
       docker build -t collateral-provider:ci .
       docker run -d --name app -p 8000:8000 \
         -e PKH=... -e DJANGO_SECRET_KEY=... [...] \
         collateral-provider:ci
       sleep 5
       curl -f http://localhost:8000/healthz
   ```

7. **CHANGELOG entry** under `[Unreleased]` documenting the deploy
   shape change.

8. **Don't forget**: update `SECURITY.md` operator checklist with the
   DO-specific hardening (TRUSTED_PROXY_IPS for DO's LB, secret
   storage, volume permissions).

## Out of scope

Don't do these in this branch — they're separate efforts:

- Migrating signing keys outside `api/key/` for the legacy single-host
  deploy (deferred per memory/project_deferred_work.md).
- Switching cache backend to Redis (premature; current scale doesn't
  need it).
- Adding observability beyond what's already in place (`/metrics`,
  request IDs, JSON logs, /healthz).

## Workflow expectations

- Run `./test.sh` after each substantive change. Suite is ~129 tests,
  ~50ms.
- Run `./lint.sh` before committing.
- Each commit is a coherent unit (Dockerfile alone, settings change
  alone, etc.) with a body explaining the *why*.
- Don't combine unrelated changes.
- If something requires a tradeoff (volume vs. baked-in for bans.json,
  for example), surface it in the chat before committing — don't make
  the call silently.
- When in doubt about DO-specific behavior, look up the docs rather
  than guessing.

## How to verify you're not done

Easy ways to fool yourself into thinking you're done when you're not:

- Local Docker build succeeds. (Doesn't prove DO build works — they
  have different defaults, e.g. read-only filesystem layers.)
- `/healthz` responds 200 locally. (Doesn't prove signing keys are
  reachable in the deployed container.)
- A git push happened. (Doesn't prove DO actually picked it up. Check
  the DO panel.)
- Tests pass. (They're stubs that mock signing-key locations and the
  Koios call. Don't catch deploy-pipeline issues.)

Verify the deploy by:
- Looking at DO's build logs after a real push
- `curl -f https://<deployed-host>/healthz` from outside DO
- A real signing request with a real preprod tx (use scripts/py/query.py)
- Checking metrics scrape from your configured allow-listed IP

Good luck. Ask the user before making any decision that touches their
production traffic — domain transfers, env-var values, secret rotation.
