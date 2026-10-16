"""Force a retrain, then keep or trash it -- without ever touching what is scoring traffic.

Each test here is one way this feature could quietly do the wrong thing:

  * a candidate that trained into the LIVE directory would replace the models before anyone judged
    them, which is the entire reason the exchange exists;
  * a report that does not say what the training window CONTAINED cannot support the decision -- a
    retrain learns whatever it is shown, and the machine cannot know whether that was an attack;
  * `keep` must archive what it replaces, because "put back what was working" has to be possible
    without re-running anything;
  * a request that cannot be carried out must become FAILED with its reason, never a permanent
    `requested` that reads as a worker which is busy.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


class _Det:
    """The smallest thing run_candidate can be given: train, metadata, save, artifact_path."""

    def __init__(self, name: str, model_dir: Path, *, trains: bool = True, rows: int = 100,
                 is_teacher: bool = False):
        self.name = name
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.trains = trains
        self.loaded = 0
        self.saved = 0
        self.trained_into = None
        self.metadata = SimpleNamespace(sample_count=rows, metrics={}, window_start=None,
                                         window_end=None)
        if is_teacher:
            self.X_train_unscaled = [[1.0, 2.0], [3.0, 4.0]]

    def train(self, *args, **kwargs) -> bool:
        self.trained_into = str(self.model_dir)
        return self.trains

    def save(self):
        (self.model_dir / self.artifact_path().name).write_bytes(b"candidate-bytes")
        self.saved += 1
        return self.model_dir / self.artifact_path().name

    def artifact_path(self) -> Path:
        return self.model_dir / f"{self.name}_v2.pkl"

    def load(self) -> bool:
        self.loaded += 1
        return True


class _Client:
    def __init__(self, rows=None, exc=None):
        self.rows, self.exc = rows or [], exc

    def query(self, sql, parameters=None):
        if self.exc:
            raise self.exc
        return SimpleNamespace(result_rows=self.rows)

    def insert(self, *a, **k):
        pass


def test_a_candidate_trains_into_its_own_directory_and_never_touches_the_live_one(tmp_path):
    from weirvern.models import retrain

    built: list[str] = []

    def build(model_dir: str):
        built.append(model_dir)
        return [_Det("Isolation Forest", Path(model_dir), is_teacher=True),
                _Det("Gradient Boosting", Path(model_dir)),
                _Det("DBSCAN", Path(model_dir), trains=False),
                _Det("Adaptive Baseline", Path(model_dir))]

    settings = SimpleNamespace(retrain_window_h=6, model_dir=str(tmp_path))
    live = tmp_path / "Isolation Forest_v2.pkl"
    live.write_bytes(b"LIVE")

    report = retrain.run_candidate(_Client(), settings, object(), build=build)

    assert built == [str(tmp_path / "candidate")], (
        "the candidate was not aimed at its own directory: a forced retrain could replace the "
        "models that are scoring traffic")
    assert live.read_bytes() == b"LIVE", "the live artifact was touched"
    assert report["trained_any"] is True
    assert (tmp_path / "candidate" / "Isolation Forest_v2.pkl").exists()
    assert report["files"], "the report does not name the artifacts a keep would install"
    rows = {d["name"]: d for d in report["detectors"]}
    assert rows["DBSCAN"]["trained"] is False and rows["Isolation Forest"]["trained"] is True
    assert all(d["sample_count"] == 100 for d in report["detectors"] if d["trained"])


def test_the_report_counts_the_detections_already_inside_the_window(tmp_path):
    from weirvern.models import retrain

    start = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    end = start + timedelta(hours=6)

    out = retrain.contamination(_Client(rows=[(3, start, end)]), start, end)
    assert out == {"available": True, "detections": 3, "first": start, "last": end}

    bad = retrain.contamination(_Client(exc=RuntimeError("Code: 47")), start, end)
    assert bad["available"] is False and "RuntimeError" in bad["reason"], (
        "an unreadable contamination count must be stated, not rendered as a clean window")


def test_the_summary_says_what_matters_and_warns_about_a_dirty_window():
    from weirvern.models import retrain

    dirty = retrain.report_summary({
        "detectors": [{"trained": True, "sample_count": 500},
                      {"trained": False, "sample_count": 0}],
        "contamination": {"available": True, "detections": 2},
    })
    assert "1 of 2 detector(s) trained" in dirty and "on 500 host-window(s)" in dirty
    assert "WARNING" in dirty and "as normal" in dirty, (
        "a window holding detections must warn beside the Keep button")

    clean = retrain.report_summary({
        "detectors": [{"trained": True, "sample_count": 10}],
        "contamination": {"available": True, "detections": 0},
    })
    assert "no detections were recorded inside the window" in clean

    assert retrain.report_summary({}) == ""


def test_keep_archives_what_it_replaces_and_reloads_the_running_detectors(tmp_path):
    from weirvern.models import retrain

    live = tmp_path / "Isolation Forest_v2.pkl"
    live.write_bytes(b"WORKING MODEL")
    cand = tmp_path / "candidate"
    cand.mkdir()
    (cand / "Isolation Forest_v2.pkl").write_bytes(b"NEW MODEL")

    dets = [_Det("Isolation Forest", tmp_path)]
    settings = SimpleNamespace(model_dir=str(tmp_path))

    out = retrain.apply_candidate(_Client(), settings, dets)

    assert out["installed"] == ["Isolation Forest_v2.pkl"]
    assert live.read_bytes() == b"NEW MODEL", "the candidate was not installed"
    archived = Path(out["archived_to"]) / "Isolation Forest_v2.pkl"
    assert archived.read_bytes() == b"WORKING MODEL", (
        "the replaced artifact was not kept: a worse retrain would not be undoable")
    assert dets[0].loaded == 1, "the running detector was not reloaded, so it keeps scoring with the old model"
    assert not cand.exists(), "the candidate directory was left behind to be installed again later"


def test_trash_removes_the_candidate_and_leaves_the_live_files_alone(tmp_path):
    from weirvern.models import retrain

    live = tmp_path / "Isolation Forest_v2.pkl"
    live.write_bytes(b"WORKING MODEL")
    cand = tmp_path / "candidate"
    cand.mkdir()
    (cand / "Isolation Forest_v2.pkl").write_bytes(b"NEW MODEL")

    out = retrain.discard_candidate(SimpleNamespace(model_dir=str(tmp_path)))

    assert out["removed"] == ["Isolation Forest_v2.pkl"]
    assert not cand.exists()
    assert live.read_bytes() == b"WORKING MODEL", "trash must never touch the live artifacts"


def test_a_keep_without_a_finished_candidate_fails_with_its_reason(monkeypatch):
    """A request that cannot be carried out is FAILED with the reason, never left in `requested`:
    a row that sits there forever looks like a worker that is busy."""
    from weirvern import worker
    from weirvern.models import actions

    finished: list[tuple] = []

    monkeypatch.setattr(actions, "pending",
                        lambda client, action: ([{"action_id": "k1", "target_id": "nope", "ts": 0,
                                                  "action": action, "state": "requested",
                                                  "requested_by": "admin", "note": "", "report": ""}]
                                                if action == actions.KEEP else []))
    monkeypatch.setattr(actions, "latest",
                        lambda client, action: {"state": "done", "action_id": "other"})
    monkeypatch.setattr(actions, "finish",
                        lambda client, aid, state, **kw: finished.append((aid, state, kw)))

    worker.process_model_actions(_Client(), [], SimpleNamespace(), object())

    assert finished and finished[0][0] == "k1"
    assert finished[0][1] == actions.FAILED
    assert "no finished candidate" in finished[0][2].get("note", ""), finished


def test_the_payload_offers_keep_only_when_something_trained():
    from weirvern.admin import web_api

    row = {"ts": datetime(2026, 1, 1, tzinfo=UTC), "action_id": "r1", "state": "done",
           "requested_by": "admin", "note": "summary",
           "report": '{"trained_any": true, "detectors": []}'}
    out = web_api.retrain_payload(row, None)
    assert out["can_keep"] is True and out["state"] == "done"

    empty = dict(row, report='{"trained_any": false}')
    assert web_api.retrain_payload(empty, None)["can_keep"] is False, (
        "an empty candidate must not be installable over working models")

    assert web_api.retrain_payload(None, None)["state"] == "none"
    bad = web_api.retrain_payload(None, None, available=False, reason="Code: 47")
    assert bad["available"] is False and "47" in bad["reason"]


def test_the_gui_pod_does_not_need_the_model_directory():
    """The request/decision channel is ClickHouse, so the panel must read everything it shows from
    the ROW. A payload that listed files from disk would render an empty candidate on a GUI pod
    that does not mount MODEL_DIR -- and the operator would trash a live candidate on its word."""
    web = (ROOT / "weirvern/admin/web.py").read_text()
    assert "candidate_files" not in web, (
        "the GUI is reading the model directory; it does not have one -- the worker owns it")
