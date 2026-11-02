# Portable ML: learning a network it has not seen

Weirvern ships no model trained on one customer's network. The detectors learn the deployment
they run in; the product contract is that the same code can start on a different address plan,
service mix and sensor coverage without a new training set.

## What is network-invariant

The feature vectors contain behaviour, not identity: bytes, packets, flow counts, destination
and port diversity, timing, connection state, protocol shape, DNS shape and novelty history.
They do not contain source addresses, destination addresses, subnets, VLAN ids, interface names,
MAC addresses or hostnames. `tests/test_ml_portability.py` pins that rule and verifies that
renaming an address plan leaves the vector unchanged.

## Warm-up is a state, not a timer

A fresh deployment is **warming**, not quiet:

- `ML_WARMUP_HOURS` (default 24) is the local history window measured at startup.
- `ML_WARMUP_MIN_WINDOWS` (default 12) and `ML_WARMUP_MIN_HOSTS` (default 1) are the minimum
  distinct windows and hosts.
- While warming, detections are still stored and visible in the console, but they **do not
  page**. The gate is `weirvern/models/readiness.py`; a failed readiness read is `unknown`
  and also does not page.
- Set `ML_WARMUP_HOURS=0` to disable the gate explicitly.

This prevents a new box from paging on a baseline it has not learned, and prevents "no data"
from being mistaken for a quiet network.

## Per-network calibration and budget

The alert tail is calibrated against the deployment's own score population
(`ML_TARGET_FAR`, `ML_CALIBRATION_DAYS`) and the episode layer enforces
`EPISODE_PAGE_BUDGET` per host per day, with a minimum severity of `EPISODE_PAGE_MIN_SEVERITY`.
Those are local decisions, not universal thresholds.

## Coverage

`zeek_present` in the feature vector distinguishes "Zeek did not observe this host-window" from
"Zeek observed it and nothing unusual happened". Missing sources are named in readiness; they
are never silently treated as normal. A flow-only network can complete warm-up; a Zeek-only
network cannot substitute for missing flow volume.

## What is not shipped

There is no global prior model, no cross-network label transfer and no claim that a model
trained on another network is valid here. Optional priors can be added later as a warm-start
prior, but local data, local calibration and local readiness remain authoritative.
