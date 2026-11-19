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

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from weirvern.models.base import BaseDetector as _BaseDetector  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class _Det:
    """The smallest thing run_candidate can be given: train, metadata, save, artifact_path."""

    def __init__(self, name: str, model_dir: Path, *, trains: bool = True, rows: int = 100,
                 is_teacher: bool = False, load_ok: bool = True):
        self.name = name
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.trains = trains
        self.loaded = 0
        self.load_ok = load_ok
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
        return self.load_ok


class _TinyDetector(_BaseDetector):
    """Picklable minimal BaseDetector stand-in for the artifact-home test.

    A class defined inside the test cannot be pickled, which is exactly what save() does.
    """

    name = "Tiny"

    def train(self, *args, **kwargs) -> bool:
        return True

    def predict(self, flow, features=None) -> float:
        return 0.0

    def is_ready(self) -> bool:
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
    # the header names each detector's own count (0.23.80), never one number for the run
    assert "1 of 2 detector(s) trained" in dirty and "500" in dirty
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


def test_a_load_failure_restores_the_archived_live_model_and_is_not_reported_installed(tmp_path):
    """A candidate that cannot load must not be called installed (GitHub #59).

    The live file was moved aside; if the reload refuses the new artifact, the old bytes have
    to go back or the next restart silently adopts the candidate we just rejected.
    """
    from weirvern.models import retrain

    live = tmp_path / "Isolation Forest_v2.pkl"
    live.write_bytes(b"WORKING MODEL")
    cand = tmp_path / "candidate"
    cand.mkdir()
    (cand / "Isolation Forest_v2.pkl").write_bytes(b"BROKEN CANDIDATE")

    det = _Det("Isolation Forest", tmp_path, load_ok=False)
    out = retrain.apply_candidate(_Client(), SimpleNamespace(model_dir=str(tmp_path)), [det])

    assert out["installed"] == []
    assert out["failed"] and out["failed"][0]["name"] == "Isolation Forest_v2.pkl"
    assert live.read_bytes() == b"WORKING MODEL", "the refused candidate was left live"
    assert det.loaded == 1, "the keep did not attempt a reload"
    assert not cand.exists(), "the refused candidate directory survived a keep"


def test_a_loaded_artifact_cannot_move_the_live_detector_to_the_candidate_directory(tmp_path):
    """GitHub #59: adopting the artifact's __dict__ moved the live detector's home to
    candidate/, which the keep then deletes -- so the next save raised or silently wrote
    nowhere. Loading must preserve the live home and the in-process error counter."""
    live = _TinyDetector(tmp_path / "live")
    cand = _TinyDetector(tmp_path / "candidate")
    cand.save()
    shutil.copy2(cand.artifact_path(), live.artifact_path())
    live.predict_errors = 7

    assert live.load() is True
    assert live.model_dir == tmp_path / "live", "the artifact redirected the live model home"
    assert live.predict_errors == 7, "the live prediction-error counter was overwritten"
    # The next save must land in the live directory, not in a deleted candidate one.
    written = live.save()
    assert written.parent == tmp_path / "live"


def test_a_centreless_dbscan_is_reported_trained_but_not_usable():
    """GitHub #60: the candidate report must state both facts, not only that a run happened."""
    from types import SimpleNamespace

    from weirvern.models import retrain

    class _Centreless:
        name = "DBSCAN"

        def is_ready(self):
            return False

        metadata = SimpleNamespace(sample_count=120,
                                   metrics={"clusters": 0, "outliers": 120},
                                   window_start=None, window_end=None)

    report = retrain._detector_report(_Centreless(), trained=False)
    assert report["trained"] is False
    assert report["usable"] is False
    assert report["metrics"]["clusters"] == 0


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


def test_the_operators_requests_are_processed_on_EVERY_cycle():
    """MEASURED ON THE DEPLOYMENT, minutes after this shipped: the call was inside the branch that
    runs only once the detectors have trained, so on a box with no training data a forced retrain
    sat at `requested` forever. That is the precise state the feature exists to prevent -- a
    request that never moves reads as a worker that is busy. It is a CYCLE-LEVEL call now, and this
    pins the indentation so a later edit cannot quietly nest it again."""
    lines = (ROOT / "weirvern/worker.py").read_text().split("\n")
    call = next(i for i, ln in enumerate(lines) if ln.strip().startswith("process_model_actions("))
    sweep = next(i for i, ln in enumerate(lines) if ln.strip().startswith("verdicts = detection_sweep("))
    call_indent = len(lines[call]) - len(lines[call].lstrip())
    sweep_indent = len(lines[sweep]) - len(lines[sweep].lstrip())
    assert call_indent == sweep_indent, (
        f"process_model_actions is nested deeper ({call_indent}) than the cycle body "
        f"({sweep_indent}): a request filed before the models have trained would never be picked up"
    )
    # And it must come BEFORE the sweep, so a retrain filed while the hub is busy is acted on in
    # the cycle the operator is watching rather than the one after it.
    assert call < sweep


def test_an_action_orphaned_by_a_restart_is_not_left_running():
    """A `running` row that outlives its worker is a lie the panel repeats: the operator reads
    "busy", waits, and nothing ever changes. One process executes these actions, so a `running` row
    at startup is orphaned by definition -- measured when a deploy rolled the pod mid-retrain."""
    from weirvern.models import actions

    finished: list[tuple] = []
    client = _Client(rows=[("r-orphan",)])

    import weirvern.models.actions as mod

    real_finish = mod.finish
    mod.finish = lambda c, aid, state, **kw: (finished.append((aid, state, kw)), True)[1]
    try:
        n = actions.reap_running(client)
    finally:
        mod.finish = real_finish

    assert n == 1 and finished and finished[0][0] == "r-orphan"
    assert finished[0][1] == actions.FAILED
    assert "restarted" in finished[0][2].get("note", ""), finished


def test_a_restart_cannot_leave_a_running_row_behind_a_RACE():
    """A one-shot reap at startup RACES the previous pod's last write -- measured on the deployment:
    a retrain filed from the console seconds before a rollout sat in `running` forever, because the
    old pod had not committed its row when the new pod looked. The race-free line is the process
    start time: anything stamped `running` before THIS process began cannot be live, whenever the
    query runs."""
    from weirvern.models import actions

    seen: dict = {}

    class _C:
        def query(self, sql, parameters=None, **_kw):
            seen["sql"], seen["params"] = sql, parameters

            class R:
                result_rows = []

            return R()

    actions.reap_running(_C())
    assert "ts <" not in seen["sql"], "the startup form must reap every running row"
    actions.reap_running(_C(), before="2026-10-16 10:00:00")
    assert "ts < %(before)s" in seen["sql"], (
        "the cycle form must only reap rows older than this process: reaping newer ones would kill "
        "the retrain that is legitimately running right now")
    assert seen["params"]["before"] == "2026-10-16 10:00:00"


def test_the_gui_pod_does_not_need_the_model_directory():
    """The request/decision channel is ClickHouse, so the panel must read everything it shows from
    the ROW. A payload that listed files from disk would render an empty candidate on a GUI pod
    that does not mount MODEL_DIR -- and the operator would trash a live candidate on its word."""
    web = (ROOT / "weirvern/admin/web.py").read_text()
    assert "candidate_files" not in web, (
        "the GUI is reading the model directory; it does not have one -- the worker owns it")


class _FinishClient:
    """Serves `actions.finish`'s read one existing row and RECORDS the state write: the report
    column's exact value is what must survive as valid JSON."""

    def __init__(self):
        self.inserts: list[tuple[str, str]] = []

    def query(self, sql, parameters=None, **_kw):
        return SimpleNamespace(result_rows=[(
            datetime(2026, 1, 1, tzinfo=UTC), "act-1", "retrain", "running",
            "candidate", "sam", "", "{}")])

    def insert(self, table, rows, column_names=None, **_kw):
        row, cols = rows[0], list(column_names or [])
        self.inserts.append((row[cols.index("state")], row[cols.index("report")]))


def test_the_done_write_survives_real_datetimes_from_the_detector_metadata(tmp_path):
    """Issue #5: `_detector_report` copied the metadata's window straight into the report, and
    that metadata is a datetime (`models/base.py`); `actions.finish` writes `json.dumps(report)`
    for the DONE state, so the write raised TypeError, the RUNNING write stayed the last one
    that landed, and the row was stuck forever -- a retrain that trained fine never finished.
    This drives the REAL path with genuine datetimes (no None stub, which serializes fine) all
    the way to the recorded INSERT, and asserts the stored column is valid JSON."""
    from weirvern.models import actions, retrain

    det = _Det("Isolation Forest", tmp_path, is_teacher=True)
    det.metadata.window_start = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    det.metadata.window_end = datetime(2026, 1, 1, 6, 0, tzinfo=UTC)

    def build(model_dir):
        # run_candidate expects the four detectors in their slots: IF, GB, DBSCAN, baseline.
        return [det,
                _Det("Gradient Boosting", Path(model_dir)),
                _Det("DBSCAN", Path(model_dir), trains=False),
                _Det("Adaptive Baseline", Path(model_dir))]

    settings = SimpleNamespace(retrain_window_h=6, model_dir=str(tmp_path))
    report = retrain.run_candidate(_Client(), settings, object(), build=build)

    row = report["detectors"][0]
    assert isinstance(row["window_start"], str), (
        "the report still carries a raw datetime; the DONE write will raise TypeError again")
    assert row["window_start"].startswith("2026-01-01T00:00")

    rec = _FinishClient()
    assert actions.finish(rec, "act-1", actions.DONE, report=report) is True
    state, stored = rec.inserts[-1]
    assert state == actions.DONE
    loaded = json.loads(stored)  # the column must hold valid JSON
    assert loaded["detectors"][0]["window_start"] == row["window_start"]


def test_the_summary_never_sums_counts_that_count_different_things():
    """Issue #37: the four sample_counts mean four different things -- the teacher's training
    windows, Isolation Forest's sample of them, DBSCAN's 20% sample, and the baseline's HOST
    count -- and the old sentence added them into one number with no referent
    (5000 + 3750 + 1000 + 90 -> "on 9840 host-window(s)"). The sentence states the window
    ONCE and gives the others their own units, or omits them."""
    from weirvern.models import retrain

    summary = retrain.report_summary({
        "detectors": [
            {"name": "Gradient Boosting", "trained": True, "sample_count": 500},
            {"name": "DBSCAN", "trained": True, "sample_count": 100},
            {"name": "Adaptive Baseline", "trained": True, "sample_count": 90},
            {"name": "Isolation Forest", "trained": False, "sample_count": 0},
        ],
        "contamination": {"available": True, "detections": 0},
    })
    assert "3 of 4 detector(s) trained" in summary, summary
    # 0.23.80: the header names each detector's own count with its own unit instead of quoting
    # one detector's number as the run's (the operator's screenshot, 2026-11-19).
    assert "500" in summary, summary
    assert "DBSCAN 100 window sample" in summary, summary
    assert "Adaptive Baseline 90 hosts" in summary, summary
    assert "590" not in summary and "690" not in summary and "9840" not in summary, (
        f"numbers from different units were summed: {summary}"
    )

def test_a_mass_failure_is_DRAINED_past_the_old_fifty_row_bound():
    """Issue #29: one LIMIT 50 pass left everything past the 50th row stranded until the next
    start (the cycle form runs per retrain cadence), so a mass failure above 50 rows needed
    several passes to clear. The reap now loops in batches until one comes back short."""
    from weirvern.models import actions

    finished: list[str] = []

    class _C:
        def __init__(self):
            self.calls = 0

        def query(self, sql, parameters=None, **_kw):
            self.calls += 1
            if self.calls == 1:
                rows = [("r-" + str(i),) for i in range(50)]
            elif self.calls == 2:
                rows = [("r-" + str(i),) for i in range(50, 60)]
            else:
                raise AssertionError("the loop kept querying after a short batch")

            class R:
                result_rows = rows

            return R()

    import weirvern.models.actions as mod

    real_finish = mod.finish
    mod.finish = lambda c, aid, state, **kw: (finished.append(aid), True)[1]
    try:
        n = actions.reap_running(_C())
    finally:
        mod.finish = real_finish

    assert n == 60, f"the second batch (rows 50-59) was stranded: reaped {n}"
    assert len(finished) == 60
