"""Headless smoke test of the Streamlit dashboard (no browser, no API key)."""

from pathlib import Path

import pytest

APP_PATH = Path(__file__).resolve().parent.parent / "app.py"
AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def test_dashboard_pages_render_and_approval_flow(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    at = AppTest.from_file(str(APP_PATH), default_timeout=90).run()
    assert not at.exception
    next(b for b in at.button if "Investigate all" in b.label).click().run()
    assert not at.exception and len(at.session_state.reports) == 19
    for page in ("Alert Management", "Investigation", "Security Logs", "Incident Reports", "Human Approval"):
        at.session_state.page = page
        at.run()
        assert not at.exception, page
    next(b for b in at.button if "Approve" in b.label).click().run()
    assert any(r.approval_status.value == "APPROVED_SIMULATED" for r in at.session_state.reports.values())
