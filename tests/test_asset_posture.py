"""The asset-posture model is a shadow scorer, not an enforcer."""
from weirvern.asset_changes import ServiceChange
from weirvern.asset_posture import MODEL_VERSION, AssetPostureModel


def _change(kind="port_opened", port=22, protocol="tcp", confidence="high"):
    return ServiceChange(kind=kind, port=port, protocol=protocol, old_value="",
                         new_value="ssh OpenSSH 9.6", confidence=confidence,
                         evidence="test")


def test_a_sensitive_new_port_scores_higher_than_a_common_one():
    model = AssetPostureModel.fit(
        [(443, "tcp", "https", "nginx", "1.24", "") for _ in range(100)]
        + [(22, "tcp", "ssh", "OpenSSH", "9.6", "") for _ in range(2)]
    )
    ssh = model.score(_change(port=22), host_services=[(443, "tcp")])
    https = model.score(_change(port=443), host_services=[(443, "tcp")])
    assert ssh.score > https.score
    assert ssh.band in ("suspicious", "high")
    assert any("sensitive service" in reason for reason in ssh.reasons)


def test_a_never_seen_port_is_novel():
    model = AssetPostureModel.fit([(443, "tcp", "https", "nginx", "1.24", "")])
    score = model.score(_change(port=8443), host_services=[(443, "tcp")])
    assert score.features["port_frequency"] == 0.0
    assert any("not been seen" in reason for reason in score.reasons)


def test_a_low_confidence_closure_is_not_loud():
    model = AssetPostureModel()
    score = model.score(_change(kind="port_closed", port=443, confidence="low"))
    assert score.score < 0.35
    assert score.band == "expected"
    assert score.model_version == MODEL_VERSION


def test_every_score_has_reasons():
    model = AssetPostureModel()
    score = model.score(_change())
    assert score.reasons
    assert 0.0 <= score.score <= 1.0
