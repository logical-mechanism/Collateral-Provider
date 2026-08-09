# Client and load-testing scripts

Examples of calling the collateral endpoint, plus the load-test harness.

| Path | What it does |
| --- | --- |
| [`bash/query.sh`](bash/query.sh) | Minimal `curl` request against a provider. |
| [`py/query.py`](py/query.py) | `collat_witness(tx_cbor, network)` — a plain `requests` call returning the witness. Edit the host constant before use; it takes no command-line arguments. |
| [`stress_test/locustfile.py`](stress_test/locustfile.py) | Locust user driving `POST /<network>/collateral/`. |

## Load testing

Point load tests at a **staging** instance with `*_KOIOS_URL` set to a local
stub evaluator, never at public Koios and never at a production provider. A
realistic run needs:

- a transaction fixture that passes every validator for the staging collateral
  UTxO (field 13 set to the staging `TXID`/`TXIDX`, the provider PKH in field 14,
  field 11 computed from the stub's cost models, and committed execution units
  at least the stub's reported budgets);
- `COLLATERAL_THROTTLE_RATE` raised out of the way when measuring the capacity
  knee, and restored when measuring what a single integrator actually sees;
- `--workers 1`, or fixed multiprocess metrics, since Prometheus counters are
  per gunicorn process.

The service's sustained ceiling is `workers * KOIOS_MAX_IN_FLIGHT` divided by
evaluator latency — roughly 16 rps at a 500 ms RTT. Requests above that budget
are shed as 503 rather than queued, so an open-loop tool (k6, vegeta) reports
far more useful numbers than a closed-loop one.
