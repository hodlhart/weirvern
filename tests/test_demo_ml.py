"""The demo ML summary must not advertise hours the cursor cannot reach."""
from dataclasses import dataclass

from weirvern import demo_ml, worker


@dataclass(frozen=True)
class _Settings:
    model_dir: str = "/tmp/weirvern-demo-ml-test"
    retrain_window_h: int = 72


def test_the_requested_span_is_clamped_to_the_model_window(monkeypatch):
    monkeypatch.setattr(worker, "model_config", lambda settings: None)
    monkeypatch.setattr(worker, "build_detectors", lambda *a, **k: [])
    monkeypatch.setattr(worker, "load_or_train", lambda *a, **k: (False, None))

    out = demo_ml.run(None, _Settings(), hours=144)

    assert out["hours_requested"] == 144
    assert out["hours"] == 72, "the summary claimed a span the detection cursor clamps away"
