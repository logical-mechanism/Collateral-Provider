"""Locust load profile for the collateral endpoint.

Run against a staging instance whose ``*_KOIOS_URL`` points at a local stub
evaluator — never against public Koios or a production provider:

    locust -f scripts/stress_test/locustfile.py --host https://staging.example

Set ``COLLATERAL_TX_CBOR`` to a transaction that passes every validator for the
staging collateral UTxO. Without it the run still exercises the HTTP path and
the validator chain, but every request stops at the first validator and the
numbers say nothing about evaluation cost.
"""

import os

from locust import HttpUser, between, task

# A transaction that reaches the upstream evaluator has to reference the
# staging collateral UTxO in body field 13 and carry the provider PKH in field
# 14, so it cannot be hardcoded here — it is specific to the instance you are
# testing.
TX_CBOR = os.environ.get("COLLATERAL_TX_CBOR", "")
NETWORK = os.environ.get("COLLATERAL_NETWORK", "preprod")


class LoadTestUser(HttpUser):
    wait_time = between(1, 5)

    @task
    def request_collateral_witness(self):
        # Go through Locust's instrumented session, not a bare requests call:
        # statistics are collected by wrapping self.client, so anything else
        # produces a run that reports zero samples. `name` keeps every network
        # under one row instead of one per URL.
        with self.client.post(
            f"/{NETWORK}/collateral/",
            json={"tx": TX_CBOR},
            name="POST /<network>/collateral/",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 429:
                # Throttling is the expected steady state above the configured
                # rate. Count it separately rather than as a server failure.
                response.failure("throttled (429)")
            else:
                response.failure(f"{response.status_code}: {response.text[:200]}")
