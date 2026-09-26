"""Tester för shallot demo incident — märkning, dramaturgi, determinism."""

import pytest
from shallot_cli import cli, incident

REQUIRED_LINES = [
    "Ändringsbegäran upptäckt",
    "Verifiering saknas eller misslyckades",
    "Åtgärd nekad — fail closed",
    "Ingen processändring genomförd",
]


def test_banner_marks_simulation_top_and_bottom():
    text = incident.render(incident.run_incident())
    assert text.splitlines()[0] == "!" * 60
    assert text.splitlines()[1].startswith("!!! SIMULERING")
    assert text.rstrip().endswith("!" * 60)
    assert text.count("SIMULERING") >= 3
    assert "verkligt OT-system" in text


def test_all_four_required_lines_present_in_order():
    text = incident.render(incident.run_incident())
    positions = [text.index(line) for line in REQUIRED_LINES]
    assert positions == sorted(positions)


def test_events_are_timestamped_and_deterministic():
    first = incident.render(incident.run_incident())
    second = incident.render(incident.run_incident())
    assert first == second
    res = incident.run_incident()
    assert [e["ts"] for e in res["events"]] == [
        "2026-09-15T10:00:00Z",
        "2026-09-15T10:00:01Z",
        "2026-09-15T10:00:01Z",
        "2026-09-15T10:00:02Z",
    ]


def test_reveal_names_shallot_and_real_command():
    text = incident.render(incident.run_incident())
    assert "SHALLOT CLI" in text
    assert "shallot simulate auth --scenario wrong-key" in text
    assert "DENIED" in text and "fail closed" in text


def test_claims_no_real_ot_data_or_hardware():
    text = incident.render(incident.run_incident())
    assert "Ingen fysisk hårdvara" in text
    for token in ["SCADA", "192.168", "10.0.0.", "100.64.", "Modbus", "Siemens"]:
        assert token not in text, token


def test_cli_demo_incident_exits_0(capsys):
    assert cli.main(["demo", "incident"]) == 0
    out = capsys.readouterr().out
    assert "SIMULERING" in out
    for line in REQUIRED_LINES:
        assert line in out


def test_cli_demo_without_subcommand_exits_2():
    with pytest.raises(SystemExit) as e:
        cli.main(["demo"])
    assert e.value.code == 2


def test_existing_flows_unchanged(capsys):
    assert cli.main(["simulate", "auth", "--scenario", "wrong-key"]) == 0
    out = capsys.readouterr().out
    assert "DENIED" in out
    assert (
        cli.main(
            [
                "protocol",
                "encode",
                "--type",
                "challenge",
                "--payload",
                "0001020304050607",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.strip() == "aa08000100010203040506071cf3b72b"
