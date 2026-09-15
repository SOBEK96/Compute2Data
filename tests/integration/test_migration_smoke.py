"""Live integration validation of the v0.3.0-migrated contract.

The gltest harness (genlayer-test 0.29.2, the newest published) cannot load or
even discover a `gl.contract.Contract`-based contract -- its direct loader raises
"unexpected end of memory" and its factory only recognizes the legacy `gl.Contract`
base. So this suite validates the migration the way the direct harness cannot: by
exercising the ALREADY-DEPLOYED contract on the real GenLayer Studio GenVM (the
py-genlayer 5jycge runner) through read-only CLI calls.

The contract was deployed to studio-dev at C2D_ADDRESS (deploy tx returned
FINISHED_WITH_RETURN / execution_result SUCCESS -- the pre-migration old-idiom
contract returned FINISHED_WITH_ERROR at the same node, which is what this
migration fixes). Read calls take no fees and are deterministic.

Run: pytest tests/integration/test_migration_smoke.py -v -s
(requires the genlayer CLI configured for studio-dev and network reachable).
"""

import json
import re
import subprocess

import pytest


C2D_ADDRESS = "0xbA6F26bbC123FE1336c719F0FE71343167D1dBa9"
RPC_URL = "https://studio-dev.genlayer.com/api"
ONE_GEN = 10**18


def _parse_js_object(text: str) -> dict:
    # Quote bare keys and convert single-quoted string values to double quotes.
    text = re.sub(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:", r'\1"\2":', text)
    text = text.replace("'", '"')
    return json.loads(text)


def _call(method: str, *args: str) -> dict:
    """Invoke a view method via the genlayer CLI and parse the JSON Result block."""
    cmd = ["genlayer", "call", C2D_ADDRESS, method, "--rpc", RPC_URL, *args]
    for _ in range(4):  # tolerate transient TLS drops to the Studio RPC
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        out = proc.stdout + proc.stderr
        if "socket disconnected" in out or "secure TLS" in out:
            continue
        start = out.find("{")
        end = out.rfind("}")
        if start != -1 and end != -1:
            return _parse_js_object(out[start : end + 1])
        raise AssertionError(f"Unexpected CLI output for {method}:\n{out}")
    raise AssertionError(f"RPC unreachable for {method}")


@pytest.mark.integration
def test_live_market_config():
    cfg = _call("get_market_config")
    assert int(cfg["minimum_dataset_stake"]) == 10 * ONE_GEN
    assert int(cfg["minimum_job_collateral"]) == 2 * ONE_GEN
    assert int(cfg["minimum_appeal_bond"]) == 1 * ONE_GEN
    assert int(cfg["total_staked"]) == 0


@pytest.mark.integration
def test_live_attestation_config():
    att = _call("get_attestation_config")
    assert att["attestation_status_ok"] == "UpToDate"
    assert len(att["sgx_root_ca_pubkey"]) == 128
    assert len(att["tcb_signing_pubkey"]) == 128
