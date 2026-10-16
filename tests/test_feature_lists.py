"""Every model sees DNS: the feature lists must all carry the DNS block.

The operator, 2026-10-16: "make sure dns is added to all ml as well." Measured: the isolation
forest's set carried the five DNS features, but the DBSCAN clustering subset did not carry ANY
-- so one of the two detectors could not see a tunnel's entropy or a resolver's error bursts at
all. These tests pin the property, not the numbers: every feature list that adds Zeek features
adds the DNS block, and the schema version moved when the shape did (artifacts are versioned by
it, so a silent shape change would reinterpret every column).
"""

from weirvern.features import DBSCAN_FEATURES, FEATURE_SCHEMA_VERSION, IF_FEATURES


def test_every_model_feature_list_that_uses_zeek_uses_dns():
    for name, features in (("IF_FEATURES", IF_FEATURES), ("DBSCAN_FEATURES", DBSCAN_FEATURES)):
        zeek = [f for f in features if f.startswith("zeek_")]
        dns = [f for f in features if f.startswith("zeek_dns")]
        assert zeek, f"{name} does not use Zeek at all"
        assert dns, (
            f"{name} uses Zeek features but NONE of the DNS block ({dns}); a detector that "
            f"cannot see resolver behaviour is blind to the traffic class the DNS features "
            f"exist for")


def test_the_dbscan_vector_carries_the_dns_triple():
    for name in ("zeek_dns_count", "zeek_dns_mean_query_entropy", "zeek_dns_rcode_error_ratio"):
        assert name in DBSCAN_FEATURES, f"{name} missing from the DBSCAN subset"


def test_the_schema_version_says_three():
    """The DBSCAN vector changed shape (16 -> 19) in the same commit; artifacts are versioned
    by this number in their filename and refused at load on a mismatch, so the bump IS the
    safety mechanism."""
    assert FEATURE_SCHEMA_VERSION >= 3
