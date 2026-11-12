"""RIP-1: the corpus must be deterministic, labelled, and honest about what it injected."""
from __future__ import annotations

import json

import pytest

from weirvern.models import ripple_corpus as corpus


def test_the_same_seed_reproduces_the_exact_same_corpus():
    a = corpus.generate(seed=7, days=2, hosts_per_scenario=1)
    b = corpus.generate(seed=7, days=2, hosts_per_scenario=1)
    c = corpus.generate(seed=8, days=2, hosts_per_scenario=1)
    assert a["manifest"]["sha256"] == b["manifest"]["sha256"]
    assert a["manifest"]["sha256"] != c["manifest"]["sha256"]


def test_every_scenario_family_is_present_and_positives_are_machine_labelled():
    payload = corpus.generate(seed=11, days=3, hosts_per_scenario=2)
    counts = payload["manifest"]["by_scenario"]
    assert set(counts) == set(corpus.SCENARIOS)
    for scenario in corpus.SCENARIOS:
        assert counts[scenario] > 0
    labelled = [h for h in payload["host_days"] if h["label"]]
    assert labelled, "a corpus without labels cannot be measured"
    assert all(h["label"]["expected"] in {"ripple", "negative"} for h in labelled)
    assert payload["manifest"]["ripple_host_days"] == sum(
        1 for h in labelled if h["label"]["expected"] == "ripple")


def test_clean_days_carry_no_label_at_all():
    payload = corpus.generate(seed=3, days=2, hosts_per_scenario=1)
    clean = [h for h in payload["host_days"] if h["scenario"] == "clean"]
    assert clean and all(h["label"] is None for h in clean)


def test_a_burst_is_exactly_one_window_and_is_never_a_ripple():
    payload = corpus.generate(seed=5, days=2, hosts_per_scenario=2)
    bursts = [h for h in payload["host_days"] if h["scenario"] == "burst"]
    assert bursts
    for item in bursts:
        label = item["label"]
        assert label["expected"] == "negative"
        assert label["end_minute"] - label["start_minute"] == corpus.BUCKET_MINUTES


def test_a_benign_new_service_is_a_real_change_that_is_still_negative():
    payload = corpus.generate(seed=9, days=2, hosts_per_scenario=2)
    benign = [h for h in payload["host_days"] if h["scenario"] == "benign_new_service"]
    assert benign
    for item in benign:
        label = item["label"]
        assert label["expected"] == "negative"
        start = label["start_minute"] // corpus.BUCKET_MINUTES
        service = f"{corpus.INTERNAL_PREFIX}50"
        assert all(service not in [dst for _, dst in bucket]
                   for bucket in item["edges"][:start]), "the service must be new, not pre-existing"
        assert any(service in [dst for _, dst in bucket]
                   for bucket in item["edges"][start:]), "the new service never appears"


def test_the_injected_change_is_inside_the_label_and_not_before_it():
    payload = corpus.generate(seed=13, days=2, hosts_per_scenario=1)
    slow = [h for h in payload["host_days"] if h["scenario"] == "low_and_slow"]
    assert slow
    for item in slow:
        label = item["label"]
        start = label["start_minute"] // corpus.BUCKET_MINUTES
        end = label["end_minute"] // corpus.BUCKET_MINUTES
        inside = sum(item["bytes_out"][start:end]) / max(1, end - start)
        before = sum(item["bytes_out"][max(0, start - 6):start]) / 6
        assert inside > before, "the labelled window must actually be elevated"
        assert label["amplitude"] >= corpus.AMPLITUDES[0]


def test_amplitude_and_duration_are_both_varied():
    payload = corpus.generate(seed=17, days=3, hosts_per_scenario=1)
    cells = {(h["label"]["amplitude"], h["label"]["end_minute"] - h["label"]["start_minute"])
             for h in payload["host_days"] if h["scenario"] == "low_and_slow"}
    assert {a for a, _ in cells} == set(corpus.AMPLITUDES)
    assert {d for _, d in cells} == set(corpus.DURATIONS)


def test_a_corpus_round_trips_and_a_tampered_corpus_is_refused(tmp_path):
    payload = corpus.generate(seed=19, days=1, hosts_per_scenario=1)
    target = tmp_path / "corpus.json"
    corpus.dump(payload, target)

    loaded = corpus.load(target)
    assert loaded["manifest"]["sha256"] == payload["manifest"]["sha256"]
    assert len(corpus.host_days(loaded)) == payload["manifest"]["host_days"]

    raw = json.loads(target.read_text())
    raw["host_days"][0]["bytes_out"][0] += 1.0
    target.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="manifest does not match"):
        corpus.load(target)


def test_a_corpus_from_another_generator_version_is_refused(tmp_path):
    payload = corpus.generate(seed=23, days=1, hosts_per_scenario=1)
    payload["generator_version"] = "ripple-corpus/999"
    target = tmp_path / "old.json"
    payload.pop("manifest", None)
    payload["manifest"] = corpus.manifest(payload)
    target.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="expects"):
        corpus.load(target)


def test_the_lateral_scenario_moves_peers_without_moving_volume():
    payload = corpus.generate(seed=31, days=2, hosts_per_scenario=2)
    lateral = [h for h in payload["host_days"] if h["scenario"] == "lateral"]
    assert lateral
    for item in lateral:
        label = item["label"]
        assert label["expected"] == "ripple"
        assert "graph" in label["channels"] and "flow" not in label["channels"]
        start = label["start_minute"] // corpus.BUCKET_MINUTES
        end = label["end_minute"] // corpus.BUCKET_MINUTES
        # The volume series is byte-identical inside and outside the labelled window.
        inside = item["bytes_out"][start:end]
        before = item["bytes_out"][max(0, start - 6):start]
        assert max(inside) < max(before) * 1.2, "a lateral ripple must not be a volume spike"
        assert any(dst.startswith(corpus.INTERNAL_PREFIX)
                   for bucket in item["edges"][start:end] for _, dst in bucket)


def test_the_dns_tunnel_scenario_is_protocol_only():
    payload = corpus.generate(seed=37, days=2, hosts_per_scenario=2)
    tunnels = [h for h in payload["host_days"] if h["scenario"] == "dns_tunnel"]
    assert tunnels
    for item in tunnels:
        label = item["label"]
        assert label["expected"] == "ripple"
        assert "dns" in label["channels"] and "flow" not in label["channels"]
        start = label["start_minute"] // corpus.BUCKET_MINUTES
        end = label["end_minute"] // corpus.BUCKET_MINUTES
        inside = item["bytes_out"][start:end]
        before = item["bytes_out"][max(0, start - 6):start]
        assert max(inside) < max(before) * 1.2, "a DNS tunnel need not move bytes"
        long_txt = [q for bucket in item["queries"][start:end] for q in bucket
                    if q["qtype"] == 16 and len(q["query"].split(".")[0]) >= 48]
        assert long_txt, "the tunnel must produce long high-entropy TXT names"
