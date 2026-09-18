from datetime import datetime

from weirvern.features import (
    DBSCAN_FEATURES,
    HOST_FEATURES,
    IF_FEATURES,
    extract_features,
    feature_vector,
)
from weirvern.zeek_features import ZEEK_DBSCAN_FEATURES, ZEEK_FEATURES


def _flow(**overrides):
    f = {
        "window_start": datetime(2026, 9, 14, 10, 30),
        "total_bytes": 1_000_000,
        "total_packets": 10_000,
        "unique_dst_ips": 5,
        "flow_count": 50,
        "avg_bytes": 20000.0,
    }
    f.update(overrides)
    return f


def test_basic_features_shape():
    feats = extract_features(_flow())
    # 10 host + 4 diversity + 2 temporal + the Zeek set. Asserted as a SUM rather than a
    # literal, so appending a feature does not need this line edited -- but a feature that
    # silently went missing still fails here.
    assert len(feats) == len(HOST_FEATURES) + 4 + 2 + len(ZEEK_FEATURES)
    assert feats["log_bytes"] > 0
    assert feats["bytes_per_packet"] == 100.0
    assert feats["is_business_hours"] == 1.0  # Tue 10:30
    assert abs(feats["hour_sin"] ** 2 + feats["hour_cos"] ** 2 - 1.0) < 1e-9


def test_business_hours_night():
    feats = extract_features(_flow(window_start=datetime(2026, 9, 14, 2, 0)))
    assert feats["is_business_hours"] == 0.0


def test_no_diversity_defaults():
    feats = extract_features(_flow())
    assert feats["port_entropy"] == 0.0
    assert feats["activity_regularity"] == 1.0
    assert feats["burstiness"] == 1.0
    assert feats["connection_density"] == 1.0


def test_diversity_populated():
    feats = extract_features(_flow(), diversity={
        "unique_dst_ports": 100, "port_entropy": 3.2, "bytes_stddev": 5000.0,
        "unique_connections": 40,
    })
    assert feats["log_unique_dst_ports"] > 0
    assert feats["port_entropy"] == 3.2
    assert abs(feats["bytes_stddev_norm"] - 0.005) < 1e-9
    assert abs(feats["connection_density"] - 0.8) < 1e-9


def test_temporal_populated():
    feats = extract_features(_flow(), temporal={"activity_regularity": 0.1, "burstiness": 4.0})
    assert feats["activity_regularity"] == 0.1
    assert feats["burstiness"] == 4.0


def test_feature_vectors_match_train_order():
    feats = extract_features(_flow(), diversity={
        "unique_dst_ports": 10, "port_entropy": 1.0, "bytes_stddev": 1.0,
        "unique_connections": 5,
    }, temporal={"activity_regularity": 0.5, "burstiness": 2.0})
    # The vector length must equal the declared feature list, which is the property that
    # actually matters: `feature_vector` rebuilds a model's input BY POSITION, so a vector
    # whose length disagrees with its column list is silently misaligned.
    assert len(feature_vector(feats, IF_FEATURES)) == len(IF_FEATURES)
    assert len(feature_vector(feats, DBSCAN_FEATURES)) == len(DBSCAN_FEATURES)
    # The Zeek features must actually be in those lists, or the wiring did nothing.
    assert "zeek_present" in IF_FEATURES, "the Zeek presence flag is not in the IF vector"
    assert ZEEK_FEATURES[0] in IF_FEATURES

    # AND the lists must end with the Zeek block in the SAME ORDER as ZEEK_FEATURES. A model
    # records its feature_columns and rebuilds its vector by name, so an order mismatch
    # produces a vector of the right length holding the wrong values -- nothing raises.
    assert IF_FEATURES[-len(ZEEK_FEATURES):] == ZEEK_FEATURES
    assert DBSCAN_FEATURES[-len(ZEEK_DBSCAN_FEATURES):] == ZEEK_DBSCAN_FEATURES
