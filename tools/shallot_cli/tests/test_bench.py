"""Tester för steg-för-steg bänkverifiering (shallot_cli.bench)."""

import json

from shallot_cli import bench, registry


def _ids() -> list[str]:
    return [s["id"] for _g, s in bench.flatten()]


def test_checklist_covers_all_open_points():
    ids = _ids()
    for prefix in ("RIGG-", "K", "H", "PRO45-", "PRO46-", "PT-"):
        assert any(i.startswith(prefix) for i in ids), prefix
    for expect in (
        "K1",
        "K2",
        "K3",
        "K4",
        "K5",
        "K6",
        "H1",
        "H2",
        "H3",
        "H4",
        "H5",
        "H6",
        "H7",
        "PT-01",
        "PT-02",
        "PT-03",
        "PT-04",
        "PT-05",
        "PT-06",
        "PT-07",
        "BG-1",
        "PNL-1",
    ):
        assert expect in ids, expect
    assert len(ids) >= 25


def test_run_list_prints_all(capsys):
    assert bench.run_list() == 0
    out = capsys.readouterr().out
    assert "Totalt" in out and "grupper" in out
    for step_id in ("RIGG-1", "K1", "H1", "PRO45-T1", "PT-01", "BG-1"):
        assert step_id in out


def _always_pass(step, index, total):
    return {"resultat": "PASS", "evidence": "loggutdrag:%s" % step["id"]}


def test_run_verify_all_pass_godkant(tmp_path):
    log = tmp_path / "bench.jsonl"
    summ = tmp_path / "bench.txt"
    res = bench.run_verify(step_fn=_always_pass, log_path=log, summary_path=summ)
    assert res["overall"] == "GODKÄNT"
    assert res["godkända"] == len(_ids())
    assert res["nekade"] == 0 and res["skippade"] == 0
    assert log.exists() and summ.exists()
    records = [json.loads(l) for l in log.read_text().splitlines()]
    assert sum(r["action"] == "step" for r in records) == len(_ids())
    assert records[-1]["action"] == "run-summary"
    assert "Inga hemligheter" in summ.read_text()


def test_run_verify_fail_nekar(tmp_path):
    def fn(step, index, total):
        return {"resultat": "FAIL" if step["id"] == "K1" else "PASS", "evidence": ""}

    res = bench.run_verify(
        step_fn=fn, log_path=tmp_path / "b.jsonl", summary_path=tmp_path / "b.txt"
    )
    assert res["overall"] == "NEKAD"
    assert res["fails"] == ["K1"]
    assert "K1" in res["verification_note"]


def test_run_verify_skipped_partial(tmp_path):
    def fn(step, index, total):
        if step["id"] in ("PT-05", "PT-06"):
            return {"resultat": "SKIP", "evidence": "ej på plats"}
        return {"resultat": "PASS", "evidence": "ok"}

    res = bench.run_verify(
        step_fn=fn, log_path=tmp_path / "b.jsonl", summary_path=tmp_path / "b.txt"
    )
    assert res["overall"] == "EJ FULLT VERIFIERAD"
    assert res["skipped"] == ["PT-05", "PT-06"]


def test_latest_none_and_after_run(tmp_path, capsys):
    assert bench.show_latest(log_path=tmp_path / "nope.jsonl") is None
    log = tmp_path / "b.jsonl"
    bench.run_verify(
        step_fn=_always_pass, log_path=log, summary_path=tmp_path / "b.txt"
    )
    last = bench.latest_result(log_path=log)
    assert last is not None and last["overall"] == "GODKÄNT"


def test_step_fn_gets_context(tmp_path):
    seen = []

    def fn(step, index, total):
        seen.append((step["id"], index, total))
        return {"resultat": "PASS", "evidence": ""}

    total = len(_ids())
    bench.run_verify(
        step_fn=fn, log_path=tmp_path / "b.jsonl", summary_path=tmp_path / "b.txt"
    )
    assert seen[0] == ("RIGG-1", 1, total)
    assert seen[-1][0] == "PNL-1"


def test_registry_has_bench_command(monkeypatch):
    from shallot_cli import serial_adapters, tui

    cmd = registry.COMMANDS["bench"]
    assert callable(cmd.run) and cmd.add_arguments
    menu = dict(registry.menu_entries())
    assert menu[30] == "Bänk: visa checklista"
    assert menu[31] == "Bänk: steg-för-steg verifiering"
    assert menu[32] == "Bänk: senaste resultat"
    assert menu[33] == "Bänk: identifiera portar (skrivskyddat)"
    assert menu[34] == "Bänk: UNO Q-konsol (bekräftas vid ändring)"
    for number in ("30", "32"):  # "31" är interaktiv och testas ej via dispatch
        assert registry.dispatch_tui(number) is True
    # "33" läser hårdvara: peka om portlistan till tom innan dispatch.
    monkeypatch.setattr(serial_adapters, "list_ports", lambda: [])
    assert registry.dispatch_tui("33") is True
    assert callable(getattr(tui, "_flow_bench_list"))
    assert callable(getattr(tui, "_flow_bench_verify"))
    assert callable(getattr(tui, "_flow_bench_latest"))
    assert callable(getattr(tui, "_flow_bench_identify"))
    assert callable(getattr(tui, "_flow_bench_unoq"))


def test_cli_bench_list(capsys):
    from shallot_cli import cli

    assert cli.main(["bench", "list"]) == 0
    out = capsys.readouterr().out
    assert "PRO45-T1" in out and "Totalt" in out


def test_verify_only_runs_subset(tmp_path):
    seen = []

    def fn(step, index, total):
        seen.append(step["id"])
        return {"resultat": "PASS", "evidence": "ok"}

    res = bench.run_verify(
        step_fn=fn,
        log_path=tmp_path / "b.jsonl",
        summary_path=tmp_path / "b.txt",
        only=["RIGG-1", "K1", "PNL-1"],
    )
    assert res["overall"] == "GODKÄNT"
    assert res["total"] == 3
    assert seen == ["RIGG-1", "K1", "PNL-1"]


def test_verify_only_unknown_id_fails():
    import pytest

    with pytest.raises(ValueError, match="okänt steg"):
        bench.run_verify(
            step_fn=_always_pass,
            only=["K99"],
            log_path="/tmp/bench-nope.jsonl",
            summary_path="/tmp/bench-nope.txt",
        )


def test_cli_verify_only_unknown_id(capsys):
    from shallot_cli import cli

    assert cli.main(["bench", "verify", "--only", "K99"]) == 2
    assert "okänt steg" in capsys.readouterr().err


def _fake_ports():
    return [
        {
            "device": "/dev/ttyACM0",
            "description": "Pico 2",
            "hwid": "USB VID:PID=2E8A:000F",
        },
        {
            "device": "/dev/ttyACM1",
            "description": "Feather RP2350",
            "hwid": "USB VID:PID=239A:814F",
        },
        {"device": "/dev/ttyS0", "description": "n/a", "hwid": "n/a"},
    ]


def _fake_read(port, baud, needles, timeout):
    if port == "/dev/ttyACM0":
        return "[PRO-47]", "[PRO-47] Waiting for key distribution from UNO Q"
    if port == "/dev/ttyACM1":
        return "[PRO-48]", "[PRO-48] Waiting for key distribution from UNO Q"
    return None, None


def test_identify_maps_ports_from_banners(tmp_path, capsys):
    log = tmp_path / "identify.jsonl"
    res = bench.run_identify(
        list_ports_fn=_fake_ports, read_fn=_fake_read, log_path=log
    )
    by_port = {m["port"]: m for m in res["mapping"]}
    assert by_port["/dev/ttyACM0"]["roll"] == "DEN"
    assert by_port["/dev/ttyACM1"]["roll"] == "PAW"
    assert by_port["/dev/ttyS0"]["roll"] == "oidentifierad"
    assert "[PRO-47]" in by_port["/dev/ttyACM0"]["bevis"]
    assert log.exists()
    records = [json.loads(l) for l in log.read_text().splitlines()]
    assert records[-1]["action"] == "identify"
    out = capsys.readouterr().out
    assert "PORTIDENTIFIERING" in out and "DEN" in out and "PAW" in out


def test_identify_duplicate_role_warns(tmp_path, capsys):
    def dup_read(port, baud, needles, timeout):
        return "[PRO-47]", "samma DEN-banner på båda"

    bench.run_identify(
        list_ports_fn=_fake_ports, read_fn=dup_read, log_path=tmp_path / "i.jsonl"
    )
    assert "Varning" in capsys.readouterr().out


def test_identify_list_failure(tmp_path, capsys):
    def boom():
        raise RuntimeError("trasig backend")

    res = bench.run_identify(list_ports_fn=boom, log_path=tmp_path / "i.jsonl")
    assert res["mapping"] == [] and "error" in res
    assert "kunde inte lista" in capsys.readouterr().out


def test_cli_identify_without_hardware(monkeypatch, capsys):
    from shallot_cli import cli, serial_adapters

    monkeypatch.setattr(serial_adapters, "list_ports", lambda: [])
    assert cli.main(["bench", "identify"]) == 0
    assert "Inga serieportar" in capsys.readouterr().out


class _FakeSerial:
    def __init__(self, lines):
        self.written = b""
        self._lines = list(lines)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def write(self, data):
        self.written += data

    def flush(self):
        pass

    def readline(self):
        if self._lines:
            return self._lines.pop(0)
        return b""


_UNOQ_LINES = [
    b"=== UNO Q Key Authority Status ===\n",
    b"Key state: GENERATED\n",
    b"Key fingerprint: 0123456789ABCDEF\n",
]


def test_unoq_status_needs_no_confirm(tmp_path, capsys):
    opened = {}

    def fake_open(port, baud=115200, timeout=1.0):
        opened["port"] = port
        return _FakeSerial(_UNOQ_LINES)

    def no_confirm(prompt):
        raise AssertionError("status ska inte bekräftas")

    rc = bench.run_unoq(
        "/dev/cu.u",
        "s",
        timeout=0.2,
        confirm_fn=no_confirm,
        serial_open_fn=fake_open,
        log_path=tmp_path / "u.jsonl",
    )
    assert rc == 0
    assert opened["port"] == "/dev/cu.u"
    out = capsys.readouterr().out
    assert "Key state: GENERATED" in out


def test_unoq_generate_declined_sends_nothing(tmp_path, capsys):
    def boom(*a, **k):
        raise AssertionError("porten får inte öppnas vid nej")

    rc = bench.run_unoq(
        "/dev/cu.u",
        "g",
        timeout=0.2,
        confirm_fn=lambda prompt: False,
        serial_open_fn=boom,
        log_path=tmp_path / "u.jsonl",
    )
    assert rc == 2
    assert "Avbrutet" in capsys.readouterr().err


def test_unoq_generate_yes_writes_and_logs(tmp_path):
    fake = _FakeSerial(_UNOQ_LINES)
    rc = bench.run_unoq(
        "/dev/cu.u",
        "G",
        timeout=0.2,
        yes=True,
        serial_open_fn=lambda *a, **k: fake,
        log_path=tmp_path / "u.jsonl",
    )
    assert rc == 0
    assert fake.written == b"g"
    records = [json.loads(l) for l in (tmp_path / "u.jsonl").read_text().splitlines()]
    assert records[-1]["action"] == "unoq"
    assert records[-1]["cmd"] == "g"
    assert "Key state: GENERATED" in records[-1]["output"]


def test_unoq_distribute_reminds_button(tmp_path, capsys):
    fake = _FakeSerial([b">> Distributing to PLC.\n"])
    rc = bench.run_unoq(
        "/dev/cu.u",
        "1",
        timeout=0.2,
        yes=True,
        serial_open_fn=lambda *a, **k: fake,
        log_path=tmp_path / "u.jsonl",
    )
    assert rc == 0 and fake.written == b"1"
    assert "A0" in capsys.readouterr().out


def test_unoq_output_is_sanitized(tmp_path):
    from shallot_cli import fido2_sanitize

    raw = b"hemlig token abcdef1234567890+/== slut\n"
    fake = _FakeSerial([raw])
    bench.run_unoq(
        "/dev/cu.u",
        "s",
        timeout=0.2,
        yes=True,
        serial_open_fn=lambda *a, **k: fake,
        log_path=tmp_path / "u.jsonl",
    )
    records = [json.loads(l) for l in (tmp_path / "u.jsonl").read_text().splitlines()]
    assert records[-1]["output"] == fido2_sanitize.sanitize(raw.decode().rstrip("\n"))


def test_unoq_open_failure(tmp_path, capsys):
    def fail(*a, **k):
        raise RuntimeError("porten låst")

    rc = bench.run_unoq(
        "/dev/cu.u",
        "s",
        timeout=0.2,
        serial_open_fn=fail,
        log_path=tmp_path / "u.jsonl",
    )
    assert rc == 1
    assert "porten låst" in capsys.readouterr().err


def test_unoq_unknown_cmd_raises():
    import pytest

    with pytest.raises(ValueError, match="okänt UNO Q-kommando"):
        bench.run_unoq("/dev/cu.u", "z", log_path="/tmp/unoq-nope.jsonl")


def test_cli_unoq_unknown_cmd(capsys):
    from shallot_cli import cli

    assert cli.main(["bench", "unoq", "--port", "/dev/x", "--cmd", "z"]) == 2
    assert "okänt UNO Q-kommando" in capsys.readouterr().err


def test_cli_unoq_status(monkeypatch, capsys):
    from shallot_cli import cli, serial_adapters

    fake = _FakeSerial(_UNOQ_LINES)
    monkeypatch.setattr(serial_adapters, "open_console", lambda *a, **k: fake)
    assert (
        cli.main(
            ["bench", "unoq", "--port", "/dev/cu.u", "--cmd", "s", "--timeout", "0.2"]
        )
        == 0
    )
    assert fake.written == b"s"
    assert "Key state" in capsys.readouterr().out


def test_record_step_validates_and_logs(tmp_path):
    log = tmp_path / "r.jsonl"
    out = bench.record_step("K1", "PASS", "evidens A", log_path=log)
    assert out["steg"] == "K1" and out["resultat"] == "PASS"
    records = [json.loads(l) for l in log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["action"] == "step"
    assert records[0]["evidence"] == "evidens A"
    import pytest

    with pytest.raises(ValueError, match="okänt steg"):
        bench.record_step("K99", "PASS", log_path=log)
    with pytest.raises(ValueError, match="ogiltigt resultat"):
        bench.record_step("K1", "KANSKE", log_path=log)
