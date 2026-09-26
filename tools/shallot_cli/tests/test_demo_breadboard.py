"""Tester för demoläge (shallot_cli.demo) — ärlighet, mock-märkning, export.

Hermetisk lagring via conftest (SHALLOT_DEMO_LOG / SHALLOT_DEMO_SUMMARY).
"""

import json

from shallot_cli import cli, demo


def _ports(*names):
    return [{"device": n, "description": n, "hwid": "h"} for n in names]


def test_precheck_epaper_never_verified(tmp_path):
    res = demo.precheck(list_ports_fn=lambda: _ports())
    comp = res["details"]["components"]["e-paper"]
    assert comp["status"] == "ej verifierad"
    assert comp["ok"] is False


def test_precheck_mock_marked_test_only(tmp_path):
    res = demo.precheck(mock=True, list_ports_fn=lambda: _ports())
    fido = res["details"]["components"]["FIDO2-nyckel"]
    assert fido["status"] == demo.MOCK_MARKER
    assert res["details"]["mock_marker"] == demo.MOCK_MARKER


def test_precheck_writes_append_only_jsonl(tmp_path):
    log = tmp_path / "log.jsonl"
    demo.precheck(list_ports_fn=lambda: _ports(), log_path=str(log))
    demo.precheck(list_ports_fn=lambda: _ports(), log_path=str(log))
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        rec = json.loads(line)
        assert rec["action"] == "precheck"


def test_run_demo_grants_on_logs_and_display(tmp_path):
    log = tmp_path / "log.jsonl"
    summary = tmp_path / "summary.txt"

    def login(user, mock):
        return 0

    def provision(role, port):
        return "aabbccdd"

    reads = iter(
        [
            (demo.PAW_SUCCESS_NEEDLES[0], "paw ok"),
            (demo.DEN_AUTH_NEEDLES[0], "den ok"),
            (demo.DEN_AUTH_NEEDLES[1], "den nekat"),
        ]
    )

    def read_until(port, needles):
        return next(reads)

    res = demo.run_demo(
        mock=False,
        pause_fn=lambda p: None,
        confirm_fn=lambda p: True,
        ask_fn=lambda p: "admin-01",
        login_fn=login,
        provision_fn=provision,
        read_until_fn=read_until,
        list_ports_fn=lambda: _ports("/dev/ttyPaw", "/dev/ttyDen"),
        log_path=str(log),
        summary_path=str(summary),
    )
    assert res["overall"] == "GODKÄNT"
    assert res["hardware_verified"] is True
    assert any(
        v["resultat"] == "ÅTKOMST" and v["display"] == "verifierad"
        for v in res["verdicts"]
    )
    assert any(
        v["moment"] == "nekat-fall" and v["resultat"] == "NEKAD"
        for v in res["verdicts"]
    )
    assert log.exists() and summary.exists()
    runs = [r for r in demo._read_jsonl(log) if r.get("action") == "run-summary"]
    assert len(runs) == 1 and runs[0]["overall"] == "GODKÄNT"


def test_run_demo_mock_marker_in_record(tmp_path):
    def login(user, mock):
        return 0

    def provision(role, port):
        return "11223344"

    def read_until(port, needles):
        return demo.DEN_AUTH_NEEDLES[1], "den"

    res = demo.run_demo(
        mock=True,
        pause_fn=lambda p: None,
        confirm_fn=lambda p: False,
        ask_fn=lambda p: "admin-01",
        login_fn=login,
        provision_fn=provision,
        read_until_fn=read_until,
        list_ports_fn=lambda: _ports("/dev/ttyPaw", "/dev/ttyDen"),
        log_path=str(tmp_path / "l.jsonl"),
        summary_path=str(tmp_path / "s.txt"),
    )
    assert res["mock_marker"] == demo.MOCK_MARKER


def test_run_demo_unverified_display_denies(tmp_path):
    """Utan presentatörsbekräftelse av skärmen skrivs ej verifierad."""

    def login(user, mock):
        return 0

    def provision(role, port):
        return "11223344"

    reads = iter(
        [
            (demo.PAW_SUCCESS_NEEDLES[0], "paw ok"),
            (demo.DEN_AUTH_NEEDLES[0], "den ok"),
            (demo.DEN_AUTH_NEEDLES[1], "den nekat"),
        ]
    )

    def read_until(port, needles):
        return next(reads)

    res = demo.run_demo(
        mock=False,
        pause_fn=lambda p: None,
        confirm_fn=lambda p: False,  # skärm EJ bekräftad
        ask_fn=lambda p: "admin-01",
        login_fn=login,
        provision_fn=provision,
        read_until_fn=read_until,
        list_ports_fn=lambda: _ports("/dev/ttyPaw", "/dev/ttyDen"),
        log_path=str(tmp_path / "l.jsonl"),
        summary_path=str(tmp_path / "s.txt"),
    )
    assert res["overall"] == "NEKAD"
    assert res["hardware_verified"] is False
    assert res["verification_note"].startswith("ej verifierad")
    verdict = [v for v in res["verdicts"] if v["moment"] == "godkänt-fall"][0]
    assert verdict["display"] == "ej verifierad"


def test_run_demo_login_failure_is_fail_closed(tmp_path):
    def login(user, mock):
        return 1

    res = demo.run_demo(
        mock=False,
        pause_fn=lambda p: None,
        confirm_fn=lambda p: True,
        ask_fn=lambda p: "admin-01",
        login_fn=login,
        provision_fn=lambda r, p: "0",
        read_until_fn=lambda p, n: (None, None),
        list_ports_fn=lambda: _ports("/dev/ttyPaw", "/dev/ttyDen"),
        log_path=str(tmp_path / "l.jsonl"),
        summary_path=str(tmp_path / "s.txt"),
    )
    assert res["overall"] == "AVBRUTET"
    assert res["error"] == "ingen giltig Admin-session"
    recs = demo._read_jsonl(tmp_path / "l.jsonl")
    assert any(r.get("action") == "aborted" for r in recs)


def test_run_demo_requires_two_ports(tmp_path):
    def login(user, mock):
        return 0

    res = demo.run_demo(
        mock=False,
        pause_fn=lambda p: None,
        confirm_fn=lambda p: True,
        ask_fn=lambda p: "admin-01",
        login_fn=login,
        provision_fn=lambda r, p: "0",
        read_until_fn=lambda p, n: (None, None),
        list_ports_fn=lambda: _ports("/dev/ttyACM0"),
        log_path=str(tmp_path / "l.jsonl"),
        summary_path=str(tmp_path / "s.txt"),
    )
    assert res["overall"] == "AVBRUTET"
    assert "två" in res["error"]


def test_show_latest_returns_last_run(tmp_path):
    log = tmp_path / "l.jsonl"
    summary = tmp_path / "s.txt"

    def login(user, mock):
        return 0

    def provision(role, port):
        return "11223344"

    reads = iter(
        [
            (demo.PAW_SUCCESS_NEEDLES[0], "paw"),
            (demo.DEN_AUTH_NEEDLES[0], "den"),
            (demo.DEN_AUTH_NEEDLES[1], "den"),
        ]
    )

    def read_until(port, needles):
        return next(reads)

    demo.run_demo(
        mock=False,
        pause_fn=lambda p: None,
        confirm_fn=lambda p: True,
        ask_fn=lambda p: "admin-01",
        login_fn=login,
        provision_fn=provision,
        read_until_fn=read_until,
        list_ports_fn=lambda: _ports("/dev/ttyPaw", "/dev/ttyDen"),
        log_path=str(log),
        summary_path=str(summary),
    )
    last = demo.latest_result(log_path=str(log))
    assert last["overall"] == "GODKÄNT"
    assert last["_log_records"] >= 1


def test_no_shown_latest_when_empty(capsys, tmp_path):
    res = demo.show_latest(log_path=str(tmp_path / "missing.jsonl"))
    assert res is None
    assert "Inga tidigare demo-resultat" in capsys.readouterr().out


def test_cli_demo_precheck_exits_0(capsys):
    assert cli.main(["demo", "precheck"]) == 0
    out = capsys.readouterr().out
    assert "Förkontroll" in out
    assert "ej verifierad" in out


def test_cli_demo_latest_without_run(capsys):
    assert cli.main(["demo", "latest"]) == 0
    assert "Inga tidigare demo-resultat" in capsys.readouterr().out
