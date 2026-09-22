"""Live integration validation of the deployed contract on GenLayer Studio-Dev.

The direct suite (tests/direct, test/) runs the contract in-process. This suite
checks the ALREADY-DEPLOYED contract on the real GenLayer Studio GenVM (the
py-genlayer 5jycge runner) through read-only CLI calls: the market parameters,
and that the deployment pins the genuine Intel SGX Root CA and advertises the
Intel SGX DCAP quote / PCS collateral formats it verifies. Read calls take no
fees and are deterministic.

Run: pytest tests/integration/test_migration_smoke.py -v -s
(requires the genlayer CLI configured for studio-dev and network reachable).
"""

import json
import re
import subprocess

import pytest


C2D_ADDRESS = "0xA12282C872FB3416763399065cA63DAcD5e78a3C"
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
    assert att["intel_root_ca_pinned"] is True
    assert att["sgx_root_ca_pubkey"] == (
        "0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5"
        "67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394"
    )
    assert att["quote_format"].startswith("Intel SGX ECDSA quote v3, cert_data_type 5")
    assert att["accepted_tcb_statuses"] == ["UpToDate"]
