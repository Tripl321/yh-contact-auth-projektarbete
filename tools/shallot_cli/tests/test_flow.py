"""Tester för shallot_cli.flow — reproducerbart 4-stegsflöde + HW-separation."""

import json

import pytest

from shallot_cli import cli, flow, sim


def test_scenarios_cover_happy_and_fail_closed():
    assert set(flow.SCENARIOS) == {
        "success", "wrong-key", "timeout", "crc", "disconnect", "late-ack", "no-key"}


def test_all_flows_match_expected():
    for name in flow.SCENARIOS:
        res = flow.run_flow(name)
        assert res["matches_expected"] is True, name
        assert [s["stage"] for s in res["stages"]] == list(flow.STAGES)


def test_success_grants_with_checkmark_and_text():
    res = flow.run_flow("success")
    assert res["result"] == "AUTHENTICATED"
    assert res["decision"] == "grant"
    assert res["reason_code"] == 0
    assert res["ack"] == "0x01"
    assert all(s["ok"] for s in res["stages"])
    assert res["epaper"] == {
        "status": "authenticated",
        "icon": "checkmark-in-circle",
        "text": "AUTHENTICATED",
    }
    assert res["fingerprint_hex"] is not None
    assert res["response_hmac_hex"] == sim.paw_answer(sim.TEST_NONCE).hex()


def test_fail_closed_scenarios_deny():
    for name in ("wrong-key", "timeout", "crc", "disconnect", "late-ack", "no-key"):
        res = flow.run_flow(name)
        assert res["result"] == "DENIED", name
        assert res["decision"] == "deny (fail closed)", name
        assert res["ack"] == "0x00", name
        assert res["epaper"]["status"] != "authenticated", name
        assert res["epaper"]["text"] is None, name


def test_expected_reason_codes():
    assert flow.run_flow("wrong-key")["reason_code"] == 5
    assert flow.run_flow("crc")["reason_code"] == 4
    assert flow.run_flow("disconnect")["reason_code"] == 6
    assert flow.run_flow("timeout")["reason_code"] == 1
    assert flow.run_flow("late-ack")["reason_code"] == 1
    assert flow.run_flow("no-key")["reason_code"] == 5


def test_no_key_stages_nothing():
    res = flow.run_flow("no-key")
    dist = res["stages"][0]
    assert dist["stage"] == "key-distribution" and dist["ok"] is False
    assert res["response_frame_hex"] is None
    assert res["response_hmac_hex"] is None
    assert res["fingerprint_hex"] is None
    # Oprovisionerad PAW-display orörd (boot visar authenticating).
    assert res["epaper"]["status"] == "authenticating"


def test_deterministic():
    assert flow.run_flow("success") == flow.run_flow("success")
    assert flow.run_flow("crc") == flow.run_flow("crc")


def test_unknown_flow():
    with pytest.raises(ValueError):
        flow.run_flow("unlock")


def test_no_secret_keys_in_output():
    secrets = [
        sim.TEST_MASTER.hex(),
        sim.WRONG_MASTER.hex(),
        sim.derive_k_mac(sim.TEST_MASTER).hex(),
        sim.derive_k_mac(sim.WRONG_MASTER).hex(),
    ]
    for name in flow.SCENARIOS:
        blob = flow.render(flow.run_flow(name))
        for s in secrets:
            assert s not in blob, (name, s[:8])


def test_render_separates_automated_from_hardware():
    text = flow.render(flow.run_flow("success"))
    assert "SIMULATED / TEST-ONLY" in text
    assert "flöde" in text and "e-paper" in text
    assert "Fysisk hårdvara" in text
    res = flow.run_flow("success")
    assert len(res["hardware_steps"]) >= 5
    assert all("id" in h and "step" in h for h in res["hardware_steps"])


def test_cli_verify_flow_single(capsys):
    assert cli.main(["verify", "flow", "--scenario", "success"]) == 0
    out = capsys.readouterr().out
    assert "SIMULATED / TEST-ONLY" in out
    assert "AUTHENTICATED" in out and "Fysisk hårdvara" in out


def test_cli_verify_flow_all(capsys):
    assert cli.main(["verify", "flow"]) == 0
    out = capsys.readouterr().out
    for name in flow.SCENARIOS:
        assert name in out
    assert "7/7 med förväntat utfall" in out


def test_cli_verify_flow_json(capsys):
    assert cli.main(["verify", "flow", "--scenario", "crc", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["scenario"] == "crc"
    assert data["matches_expected"] is True
    assert data["result"] == "DENIED"
    assert len(data["stages"]) == 4


def test_cli_verify_flow_json_all(capsys):
    assert cli.main(["verify", "flow", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == len(flow.SCENARIOS)
    assert all(r["matches_expected"] for r in data)
