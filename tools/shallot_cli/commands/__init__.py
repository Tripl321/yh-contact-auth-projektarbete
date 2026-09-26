"""Kommandon för shallot-CLI:t. Varje modul äger ett toppkommandos logik."""

from shallot_cli.commands import (
    admin_cmd,
    build_cmd,
    device_cmd,
    doctor_cmd,
    explain_cmd,
    fido2_cmd,
    mamabear_cmd,
    monitor_cmd,
    protocol_cmd,
    test_cmd,
)

__all__ = [
    "admin_cmd",
    "build_cmd",
    "device_cmd",
    "doctor_cmd",
    "explain_cmd",
    "fido2_cmd",
    "mamabear_cmd",
    "monitor_cmd",
    "protocol_cmd",
    "test_cmd",
]
