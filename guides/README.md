# Server Setup Guides

Server setup now lives in [`docs/`](../docs/):

- [docs/DEPLOY.md](../docs/DEPLOY.md) — DigitalOcean App Platform. This is how
  the reference provider deploys: it builds the Dockerfile and ships
  automatically on every push to `main`.
- [docs/UBUNTU_DEPLOY.md](../docs/UBUNTU_DEPLOY.md) — self-hosting on a single
  Ubuntu/systemd host, for operators who would rather not depend on a
  platform. Covers the sandboxed unit, the SSH forced command, nginx/TLS, and
  the rollback and recovery runbooks.
- [docs/WALLET_INTEGRATION.md](../docs/WALLET_INTEGRATION.md) — the contract for
  wallet and transaction-builder implementers.
- [SECURITY.md](../SECURITY.md) — operator hardening checklist and the pre-hard-fork
  collateral rotation procedure.
