"""The fingerprint lookup -- "which hosts present this stack?" -- and the alert-side block.

The identity card answers "what does this host run?". This lookup answers the question an analyst
actually arrives with, pointing the other way: a fingerprint seen in one alert, then every other
host that presents it.

Three properties are pinned, each because its failure mode is silent:
  * the token is a query PARAMETER, never interpolation. A JA4 fingerprint is
    attacker-influenced -- it is the remote's own ClientHello -- and this is the one endpoint that
    takes one straight from the URL;
  * a lookup that found nothing says NOTHING FOUND with a count of zero: not an error, and not a
    claim about the world (the records only cover what the sensor retained);
  * a database failure carries the reason and an EMPTY list, because the route turns it into a
    503 -- and an empty list without a reason reads as "nobody uses this".
"""

from datetime import UTC
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class _Res:
    def __init__(self, rows):
        self.result_rows = rows


class FakeClient:
    def __init__(self, rows=None, exc=None):
        self.rows = rows or []
        self.exc = exc
        self.sql = None
        self.parameters = None

    def query(self, sql, parameters=None):
        self.sql = sql
        self.parameters = parameters
        if self.exc:
            raise self.exc
        return _Res(self.rows)


def test_the_fingerprint_is_a_query_parameter_never_interpolation():
    from weirvern.admin import status

    tok = "t13d1516h2_8daaf6152771_02713d6af862"
    client = FakeClient(rows=[("198.51.100.7", 18, None, None, 4)])
    status.fingerprint_hosts(client, tok)
    assert client.parameters and client.parameters["f"] == tok
    assert tok not in client.sql, "the fingerprint was interpolated into the SQL"
    assert "%(f)s" in client.sql


def test_the_rows_become_hosts_with_counts_and_dates():
    from datetime import datetime

    from weirvern.admin import status

    first = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    last = datetime(2026, 1, 2, 9, 0, tzinfo=UTC)
    client = FakeClient(rows=[("203.0.113.42", 18, first, last, 4)])
    out = status.fingerprint_hosts(client, "t13d1516h2_8daaf6152771_02713d6af862")
    assert out["count"] == 1
    h = out["hosts"][0]
    assert h["src_addr"] == "203.0.113.42" and h["sessions"] == 18 and h["peers"] == 4
    assert str(h["first_seen"]).startswith("2026-01-01")
    assert str(h["last_seen"]).startswith("2026-01-02")


def test_an_empty_fingerprint_is_refused_before_any_query():
    from weirvern.admin import status

    client = FakeClient()
    out = status.fingerprint_hosts(client, "   ")
    assert out["count"] == 0 and "no fingerprint given" in out["reason"]
    assert client.sql is None, "an empty token still reached the database"


def test_a_failed_query_reports_the_reason_and_an_empty_list():
    from weirvern.admin import status

    client = FakeClient(exc=RuntimeError("Code: 47"))
    out = status.fingerprint_hosts(client, "t13d1516h2_8daaf6152771_02713d6af862")
    assert out["hosts"] == [] and out["count"] == 0
    assert "RuntimeError" in out["reason"], (
        "a dead query must be distinguishable from a lookup that found nothing")


def test_the_dashboard_reads_the_fields_the_api_writes():
    """Cross-file contract, in the direction that has broken before: the payload keys the
    renderer reads must be the keys the server writes, and the routes the renderer calls must
    exist on the server. A typo on either side renders an empty panel that looks like a quiet
    network -- the failure class this project has hit twice."""
    status_src = (ROOT / "weirvern/admin/status.py").read_text()
    app = (ROOT / "weirvern/admin/web/app.js").read_text()
    html = (ROOT / "weirvern/admin/web/index.html").read_text()
    web = (ROOT / "weirvern/admin/web.py").read_text()
    api = (ROOT / "weirvern/admin/web_api.py").read_text()

    assert '"zeek_ssl": []' in status_src, "alert_evidence stopped writing the ssl section"
    assert "d.zeek_ssl" in app and 'id="ev-tls"' in html, (
        "the renderer and the payload disagree about the TLS section")
    assert '"zeek_ssl": evidence_rows' in api, "the API stopped serialising zeek_ssl"
    assert '"/api/fingerprints"' in web, "the fingerprints route is gone"
    assert "API.fingerprints" in app, "the lookup no longer calls the route"
    assert "API.sluiceBlock" in app and 'sluiceBlock: "/api/sluice/block"' in app


def test_the_worker_reads_detections_when_only_the_threshold_is_set():
    """The auto-block threshold is a SECOND reason to read detections. Reading them only for a
    policy above Off would make SLUICE_AUTO_SCORE silently inert -- the exact defect class the
    JA4 novelty audit found (a feature computed for one caller and never for the other)."""
    worker = (ROOT / "weirvern/worker.py").read_text()
    assert 'sluice_criticality != "off" or auto_score > 0.0' in worker
    assert "auto_score=auto_score," in worker
    config = (ROOT / "weirvern/config.py").read_text()
    assert 'SLUICE_AUTO_SCORE' in config
