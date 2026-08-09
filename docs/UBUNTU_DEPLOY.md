# Self-hosting on Ubuntu

**This is not how www.giveme.my is deployed.** That instance runs on
DigitalOcean App Platform ([docs/DEPLOY.md](DEPLOY.md)). This document is for
operators who want to run their own collateral provider on hardware they
control, without depending on a platform.

Everything below is self-contained: the layout, the accounts, the systemd
unit, the nginx front end, and the release mechanism are yours to own. Nothing
here needs to match the reference deployment, and the checked-in hostname
`www.giveme.my` is a placeholder you should replace throughout.

The design is a single Ubuntu 24.04 host. A manually dispatched GitHub Actions
job streams an exact commit as a tar archive over SSH to a restricted forced
command. The server builds an immutable release, switches a symlink, restarts
gunicorn through systemd, and rolls back automatically if the local readiness
probe fails. Deploys are deliberately manual and approval-gated — the opposite
trade-off from the reference deployment's push-to-`main` autodeploy.

The deploy channel carries source code only. `DJANGO_SECRET_KEY`, collateral
configuration, and `payment.skey` / `payment.vkey` are created on the server
and must never be stored in GitHub variables, secrets, artifacts, the checkout,
or a release archive.

The checked-in templates assume `www.giveme.my` and gunicorn on
`127.0.0.1:8000`. If the existing host uses another local port or hostname,
change the systemd unit, nginx upstream, deploy helper health URL, health-host
file, and `ALLOWED_HOSTS` together before installing the assets.

## Layout and trust boundaries

| Path/account | Purpose |
| --- | --- |
| `collateral-provider` | Unprivileged runtime user; can read signing keys and write only service state |
| `collateral-deploy` | SSH forced-command user; owns releases, but cannot read runtime keys or environment |
| `/srv/collateral-provider/releases/<sha>` | Versioned application and virtualenv |
| `/srv/collateral-provider/current` | Release systemd starts |
| `/srv/collateral-provider/previous` | Last release retained for rollback |
| `/etc/collateral-provider/` | Root-managed environment, keys, and health-probe Host |
| `/var/lib/collateral-provider/` | Runtime cache/state |

The deployment account needs `/bin/bash` because OpenSSH runs the forced
command through the account's shell. Do not give it an interactive key, add it
to the `collateral-provider` group, or make the server-only environment/key
files readable by it.

## 1. Install packages and accounts

Run these commands from an existing administrator session:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends \
  ca-certificates curl nginx openssh-server python3.12 python3.12-venv sudo

sudo useradd --system --user-group --create-home \
  --home-dir /var/lib/collateral-provider \
  --shell /usr/sbin/nologin collateral-provider
sudo useradd --user-group --create-home \
  --home-dir /var/lib/collateral-deploy \
  --shell /bin/bash collateral-deploy
sudo passwd --lock collateral-deploy

sudo install -d -o collateral-deploy -g collateral-deploy -m 0755 \
  /srv/collateral-provider /srv/collateral-provider/releases
sudo install -d -o collateral-provider -g collateral-provider -m 0750 \
  /var/lib/collateral-provider/cache

# Root owns the SSH authorization path so deployed code cannot replace it.
sudo chown root:root /var/lib/collateral-deploy
sudo chmod 0755 /var/lib/collateral-deploy
sudo install -d -o root -g root -m 0755 /var/lib/collateral-deploy/.ssh
sudo touch /var/lib/collateral-deploy/.ssh/authorized_keys
sudo chown root:root /var/lib/collateral-deploy/.ssh/authorized_keys
sudo chmod 0644 /var/lib/collateral-deploy/.ssh/authorized_keys

# The top-level config directory is traversable for the public health-host
# file. The key directory itself remains private to the runtime group.
sudo install -d -o root -g root -m 0755 /etc/collateral-provider
sudo install -d -o root -g collateral-provider -m 0750 \
  /etc/collateral-provider/keys
```

The host needs outbound DNS and HTTPS access to the Python package index while
building a new release, and to the configured Koios endpoints at runtime.

If either account already exists, inspect it with `getent passwd` and `id`
instead of recreating it. In particular, `id collateral-deploy` must not list
the `collateral-provider` group.

## 2. Install the root-owned deployment assets

From a trusted checkout of this repository on the server:

```bash
sudo install -o root -g root -m 0755 \
  deploy/collateral-provider-deploy \
  /usr/local/sbin/collateral-provider-deploy
sudo install -o root -g root -m 0644 \
  deploy/collateral-provider.service \
  /etc/systemd/system/collateral-provider.service
sudo install -o root -g root -m 0440 \
  deploy/collateral-provider.sudoers \
  /etc/sudoers.d/collateral-provider-deploy
sudo visudo -cf /etc/sudoers.d/collateral-provider-deploy
sudo systemctl daemon-reload
sudo systemctl enable collateral-provider.service
```

The sudo rule permits exactly three privileged commands against this service:
reset its failed/start-limit state, restart it, plus stop it when a failed
first-ever release has no prior version to restore. Resetting the start limit
before each restart ensures a fast-crashing candidate cannot prevent the old
release from starting during rollback. The forced command itself remains
root-owned. When any checked-in asset changes, review and reinstall it manually
before deploying code that depends on the new behavior.

## 3. Create server-only runtime configuration

Transfer the Cardano CLI key files to an administrator-owned temporary
location, then install them without placing them in the checkout:

```bash
sudo install -o root -g collateral-provider -m 0640 \
  /secure/source/payment.skey \
  /etc/collateral-provider/keys/payment.skey
sudo install -o root -g collateral-provider -m 0640 \
  /secure/source/payment.vkey \
  /etc/collateral-provider/keys/payment.vkey
```

Create the environment with `sudoedit /etc/collateral-provider/environment`.
This is a systemd `EnvironmentFile`, not a shell script. Quote values that
contain spaces or special characters:

```ini
PKH='REPLACE_WITH_PAYMENT_KEY_HASH'
DJANGO_SECRET_KEY='REPLACE_WITH_A_LONG_RANDOM_VALUE'
ENVIRONMENT=production
ALLOWED_HOSTS=www.giveme.my

PREPROD_TXID='REPLACE_WITH_64_HEX_CHARACTERS'
PREPROD_TXIDX=0
PREPROD_NETWORK='--testnet-magic 1'
MAINNET_TXID='REPLACE_WITH_64_HEX_CHARACTERS'
MAINNET_TXIDX=0
MAINNET_NETWORK=--mainnet

SKEY_PATH=/etc/collateral-provider/keys/payment.skey
VKEY_PATH=/etc/collateral-provider/keys/payment.vkey
BANS_PATH=/etc/collateral-provider/bans.json
TRUSTED_PROXY_IPS=127.0.0.1,::1
LOG_TO_CONSOLE=True
LOG_FORMAT=json
LOG_LEVEL=INFO
```

`CACHE_DIR` is deliberately absent: the unit file sets it to the systemd-managed
`/var/cache/collateral-provider`, so the throttle has a writable home with no
operator action. Setting it here still overrides that, but any replacement must
be writable by the service user — `ProtectSystem=strict` mounts
`/srv/collateral-provider` read-only, so a path inside the release tree fails.
`/healthz` round-trips the cache and returns 503 if it cannot, which makes a bad
value fail the deployment's readiness gate and roll back rather than going live.

`BANS_PATH` matters for the same reason: without it the default lands inside the
read-only release tree, where the file does not exist, and the address/IP ban
list silently never loads. Create it (see `bans.json.example`) or accept that
bans are inactive. `KNOWN_HOSTS_PATH` may be pointed at
`/etc/collateral-provider/known.hosts.json` if you want to edit the published
registry without a deploy; otherwise the copy in the release tree is served.

Then lock it down and configure the Host used by the direct-to-gunicorn
readiness check. It must be present in `ALLOWED_HOSTS`:

```bash
sudo chown root:root /etc/collateral-provider/environment
sudo chmod 0600 /etc/collateral-provider/environment
printf '%s\n' 'www.giveme.my' \
  | sudo tee /etc/collateral-provider/health-host >/dev/null
sudo chown root:root /etc/collateral-provider/health-host
sudo chmod 0644 /etc/collateral-provider/health-host
```

PID 1 reads the mode-0600 environment before dropping privileges. The
application reads only the two group-readable key files. Verify permissions
without printing secret contents:

```bash
sudo namei -l /etc/collateral-provider/environment
sudo namei -l /etc/collateral-provider/keys/payment.skey
sudo -u collateral-deploy test ! -r /etc/collateral-provider/environment
sudo -u collateral-deploy test ! -r /etc/collateral-provider/keys/payment.skey
```

## 4. Configure nginx and TLS

Obtain a certificate for the production hostname using your ACME client, then
install [the nginx template](../deploy/nginx-collateral-provider.conf). Replace
the hostname and certificate paths if they differ:

```bash
sudo install -o root -g root -m 0644 \
  deploy/nginx-collateral-provider.conf \
  /etc/nginx/sites-available/collateral-provider
sudo ln -s /etc/nginx/sites-available/collateral-provider \
  /etc/nginx/sites-enabled/collateral-provider
sudo nginx -t
sudo systemctl reload nginx
```

Keep gunicorn bound to `127.0.0.1:8000`; expose only SSH and nginx's HTTP/TLS
ports in the host/cloud firewall. The template disables nginx access logs so
transaction callers' IP addresses are not routinely retained. Its error log
can still contain operational metadata, so set an appropriate retention
policy. Review the HSTS policy before enabling it on a hostname with existing
HTTP-only users or subdomains.

The application returns its structured JSON response for bodies above its
36 KiB limit. nginx's 64 KiB ceiling is a secondary abuse bound; requests
larger than that receive nginx's own 413 response.

## 5. Add the forced SSH key

Generate a dedicated Ed25519 key pair on an administrator workstation. An
unencrypted private key is required for unattended Actions use, so this key
must be dedicated to this forced command:

```bash
ssh-keygen -t ed25519 -f collateral-provider-production-deploy \
  -C github-actions-collateral-provider
```

Use `sudoedit /var/lib/collateral-deploy/.ssh/authorized_keys` to add its public
half on one line, prefixed exactly as follows:

```text
restrict,command="/usr/local/sbin/collateral-provider-deploy" ssh-ed25519 AAAA... github-actions-collateral-provider
```

`restrict` disables PTY allocation, forwarding, agent forwarding, and X11.
The server script separately rejects every original command except
`deploy <40-lowercase-hex-sha>` and validates the tar archive's Git commit
metadata against that SHA.

Test from the workstation with a deliberately invalid command. It must fail
with `only 'deploy <sha>' is allowed` and never open a shell:

```bash
ssh -i collateral-provider-production-deploy collateral-deploy@www.giveme.my shell
```

## 6. Configure the GitHub `production` environment

Create a repository Environment named `production`, protect it with required
reviewers, prevent the person who dispatched a deployment from approving their
own run, and restrict it to the `production` branch. Configure these values:

| Kind | Name | Value |
| --- | --- | --- |
| Variable | `DEPLOY_HOST` | SSH hostname or address |
| Variable | `DEPLOY_PORT` | SSH port, normally `22` |
| Variable | `DEPLOY_USER` | `collateral-deploy` |
| Variable | `PUBLIC_HEALTH_URL` | `https://www.giveme.my/healthz` |
| Secret | `DEPLOY_SSH_PRIVATE_KEY` | Entire dedicated private key |
| Secret | `DEPLOY_KNOWN_HOSTS` | One pinned SSH host-key line |

Derive `DEPLOY_KNOWN_HOSTS` from the server console, not from an unauthenticated
`ssh-keyscan`. On the server, display and fingerprint the Ed25519 host key:

```bash
sudo cat /etc/ssh/ssh_host_ed25519_key.pub
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

After verifying that fingerprint through the server provider's console, make
the secret one line in known_hosts format:

```text
www.giveme.my ssh-ed25519 AAAAC3...
```

For a nonstandard port, the first field must be `[www.giveme.my]:2222`. Never
use `StrictHostKeyChecking=no`. No signing key, app secret, PKH, collateral
UTxO, or Koios credential belongs in the GitHub environment.

Protect the `production` branch so only reviewed, passing commits can reach
it. The workflow itself also refuses dispatches from any other branch and
deploys `GITHUB_SHA`, not a mutable server-side branch checkout. GitHub only
offers a `workflow_dispatch` workflow after that workflow file exists on the
repository's default branch. Land the workflow on default `main` first, then
promote the same workflow file to `production`; it must exist on both branches
before the first production dispatch.

## 7. First deploy and verification

If this replaces a manually launched or differently managed gunicorn, identify
and stop that old process immediately before the first workflow run; two
masters cannot bind the same port. Confirm what owns the template port with
`sudo ss -ltnp 'sport = :8000'`. This migration has the same brief planned
downtime as an ordinary single-host restart.

In GitHub Actions, select **Deploy production**, choose the `production`
branch, and click **Run workflow**. The server will:

1. cap and safely extract the archive, rejecting links, traversal, secrets,
   special files, oversized content, or mismatched commit metadata;
2. create a Python 3.12 virtualenv and install the locked requirements;
3. run `pip check`, Django's deployment checks, `compileall`, and
   `collectstatic` with non-secret build-only settings;
4. atomically update `previous` and `current`, then restart systemd;
5. require `/healthz` on `127.0.0.1` with the configured Host to return
   `{"status":"ok"}` within 30 seconds; and
6. restore and restart the prior release if readiness fails.

After the first success:

```bash
sudo systemctl status collateral-provider.service
sudo journalctl -u collateral-provider.service --since '10 minutes ago'
curl -fsS https://www.giveme.my/healthz
readlink -f /srv/collateral-provider/current
```

Deployments are serialized with both GitHub concurrency and server-side
`flock`. Five releases are retained, always protecting the `current` and
`previous` targets.

## Downtime, rollback, and recovery

This single-instance design uses `systemctl restart`, so each successful
deployment has a brief gunicorn restart window in which nginx can return 502.
The action does not report success until readiness passes. Zero-downtime
deploys require a later blue/green or socket-activation design.

Automatic rollback is driven by the authoritative server-local probe. The
final public probe can still fail the Actions run (for example, because DNS or
the runner's network is unhealthy), but it does not roll back a release that
the server itself has already proven healthy.

On failed readiness, the forced command atomically restores the original
links, restarts the old release, verifies it, removes a newly built failed
release, and exits nonzero. If both the candidate and rollback fail, inspect:

```bash
sudo journalctl -u collateral-provider.service -n 200 --no-pager
sudo systemctl status collateral-provider.service
```

For a normal audited rollback, revert the bad change on `production` and run
the workflow again. For an emergency console rollback to the already-built
`previous` release, wait for any active deployment action to finish, enter a
root shell, acquire the same deployment lock, verify both targets are SHA-named
directories under `/srv/collateral-provider/releases`, then swap them
atomically and restart:

```bash
sudo -i
set -euo pipefail
lock_file=/srv/collateral-provider/.deploy.lock
if [[ ! -f "$lock_file" || -L "$lock_file" ]]; then
  echo 'deployment lock is missing or unsafe' >&2
  exit 1
fi
exec 9<>"$lock_file"
if ! flock -n 9; then
  echo 'a deployment is still active' >&2
  exit 1
fi
old_current=$(readlink /srv/collateral-provider/current)
rollback_release=$(readlink /srv/collateral-provider/previous)
release_pattern='^/srv/collateral-provider/releases/[0-9a-f]{40}$'
if [[ ! "$old_current" =~ $release_pattern \
  || ! "$rollback_release" =~ $release_pattern \
  || ! -d "$old_current" || -L "$old_current" \
  || ! -d "$rollback_release" || -L "$rollback_release" ]]; then
  echo 'refusing unexpected release paths' >&2
  exit 1
fi
current_temp="/srv/collateral-provider/.current.rollback.$$"
previous_temp="/srv/collateral-provider/.previous.rollback.$$"
if [[ -e "$current_temp" || -L "$current_temp" \
  || -e "$previous_temp" || -L "$previous_temp" ]]; then
  echo 'refusing pre-existing rollback temp paths' >&2
  exit 1
fi
ln -sT -- "$rollback_release" "$current_temp"
ln -sT -- "$old_current" "$previous_temp"
mv -Tf -- "$current_temp" /srv/collateral-provider/current
mv -Tf -- "$previous_temp" /srv/collateral-provider/previous
systemctl reset-failed collateral-provider.service
systemctl restart collateral-provider.service
curl -fsS -H 'Host: www.giveme.my' http://127.0.0.1:8000/healthz
exit
```

If the emergency release is not healthy, swap the saved targets back and
investigate the runtime configuration before another restart.

Signing-key or application-environment rotation is a separate, server-only
operation. Install replacements atomically with root ownership and the modes
above, restart the service, and verify both local and public `/healthz`. A code
deploy never copies, overwrites, backs up, or rolls back those secrets.
