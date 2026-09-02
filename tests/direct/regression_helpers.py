"""Shared helpers for the Compute2Data regression suite.

This module reuses the attestation and lifecycle helpers already defined in
the primary direct-test conftest so the regression tests reproduce the exact
bytes the contract signs and re-derives on chain. Reusing a single source of
truth prevents the test fixtures from silently drifting away from the contract
crypto. Two regression-only clock helpers are added on top:

  * clear_clock(direct_vm): force gl.message_raw['datetime'] to empty so that
    the contract's _now_epoch() returns 0. This models the consensus clock
    being unavailable at job creation, which is the only way a stored deadline
    becomes zero and the liveness-fallback cancellation path is exercised.

  * iso_from_epoch(epoch): render a Unix epoch second back into the ISO-8601
    Zulu string the VM warp accepts, so tests can land the clock exactly on a
    stored deadline boundary.
"""

import datetime as _dt
import os as _os
import sys as _sys


# Make the primary test/conftest.py importable as a plain module so we can
# reuse its attestation builders without duplicating the crypto derivation.
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_PRIMARY_TEST_DIR = _os.path.join(_ROOT, "test")
if _PRIMARY_TEST_DIR not in _sys.path:
    _sys.path.insert(0, _PRIMARY_TEST_DIR)

from conftest import (  # noqa: E402  (path set up above)
    DATASET_COMMITMENT,
    DATASET_STAKE,
    INPUT_COMMITMENT,
    JOB_COLLATERAL,
    JOB_PRICE,
    MODEL_ID,
    ONE_GEN,
    OUTPUT_COMMITMENT,
    address_hex,
    build_attestation_quote,
    build_attestation_quote_with_binding_mismatch,
    fund_job,
    future_iso,
    inconclusive_assessment,
    rejected_assessment,
    stake_and_register,
    valid_assessment,
    warp,
)


CONTRACT_PATH = "contracts/c2d_marketplace.py"


def clear_clock(direct_vm) -> None:
    """Force the live gl.message_raw['datetime'] to empty.

    The contract reads this field in _now_epoch(); an empty value yields 0,
    which is exactly the clock-unavailable condition that stores a zero
    deadline on a freshly funded job. direct_vm is accepted for signature
    symmetry with warp() even though only the cached message dict is patched.
    """
    if "genlayer.gl" in _sys.modules:
        msg_raw = getattr(_sys.modules["genlayer.gl"], "message_raw", None)
        if isinstance(msg_raw, dict):
            msg_raw["datetime"] = ""


def iso_from_epoch(epoch) -> str:
    """Render a Unix epoch second as an ISO-8601 UTC string with a Z suffix."""
    stamp = _dt.datetime.fromtimestamp(int(epoch), _dt.timezone.utc)
    return stamp.isoformat().replace("+00:00", "Z")


__all__ = [
    "CONTRACT_PATH",
    "DATASET_COMMITMENT",
    "DATASET_STAKE",
    "INPUT_COMMITMENT",
    "JOB_COLLATERAL",
    "JOB_PRICE",
    "MODEL_ID",
    "ONE_GEN",
    "OUTPUT_COMMITMENT",
    "address_hex",
    "build_attestation_quote",
    "build_attestation_quote_with_binding_mismatch",
    "clear_clock",
    "fund_job",
    "future_iso",
    "inconclusive_assessment",
    "iso_from_epoch",
    "rejected_assessment",
    "stake_and_register",
    "valid_assessment",
    "warp",
]
