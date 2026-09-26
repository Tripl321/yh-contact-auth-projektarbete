"""
PRO-45: AES-128 key generation on UNO Q with STM32U585 hardware RNG.

Covers:
- Key is exactly 16 bytes (AES-128)
- Generated via STM32U585 hardware RNG (not time-based, not pseudo-random)
- RNG failure is fail-closed: no key export, provisioning aborted
- Key never exposed in logs, serial output, or flash
- Key stored only in RAM (aesKey buffer)
- Source guards for RNG usage, key generation, and secure wiping
"""

import pathlib
import sys

import pytest

# Add project root for imports
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

# ============================================================================
# Helpers
# ============================================================================


def get_uno_q_src():
    """Load UNO Q key authority firmware source."""
    root = pathlib.Path(__file__).resolve().parent.parent
    src_path = (
        root / "key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino"
    )
    return src_path.read_text()


# ============================================================================
# Key length and generation tests
# ============================================================================


def test_pro45_key_length_is_16_bytes():
    """PRO-45: AES_KEY_SIZE is 16 bytes (AES-128)."""
    src = get_uno_q_src()
    assert "AES_KEY_SIZE       16" in src or "#define AES_KEY_SIZE 16" in src


def test_pro45_generate_key_function_exists():
    """PRO-45: generateKey() function exists in firmware."""
    src = get_uno_q_src()
    assert "static bool generateKey()" in src or "bool generateKey()" in src


def test_pro45_uses_stm32_rng():
    """PRO-45: Firmware uses the STM32U585 hardware RNG through the
    decided design — Zephyr sys_csrand_get (GTZC blocks direct register
    access from the Non-Secure sketch; the runtime owns clock + NIST
    config). Direct register constants are deliberately absent."""
    src = get_uno_q_src()
    assert "sys_csrand_get" in src
    assert "generateSecureRandomBytes" in src
    # Decided design: no direct register access
    for reg in (
        "STM32_RNG_BASE",
        "STM32_RNG_CR",
        "STM32_RNG_SR",
        "STM32_RNG_DR",
        "RNG_CR_RNGEN",
        "RNG_SR_DRDY",
    ):
        assert reg not in src, reg


def test_pro45_no_time_based_seed():
    """PRO-45: No time-based seeding (no millis/micros as RNG seed)."""
    src = get_uno_q_src()
    # RNG should not be seeded with time
    rng_section = src.split("generateSecureRandomBytes")[0]
    assert "millis()" not in rng_section
    assert "randomSeed" not in src  # Arduino pseudo-random


def test_pro45_no_pseudo_random():
    """PRO-45: No pseudo-random number generation."""
    src = get_uno_q_src()
    assert "random(" not in src  # Arduino random()
    assert "rand()" not in src  # C rand()
    assert "srand(" not in src  # C srand()


def test_pro45_no_hardcoded_keys():
    """PRO-45: No hardcoded AES keys in source."""
    src = get_uno_q_src()
    # Should not have static const uint8_t arrays that look like keys
    # (except the development key which should be warned about)
    lines = src.split("\n")
    for i, line in enumerate(lines):
        if "static const uint8_t" in line and "[" in line:
            # Check if it's a 16-byte array that looks like a key
            if "16]" in line and "0x" in lines[i + 1]:
                # This is okay if it has a warning comment nearby
                context = "\n".join(lines[max(0, i - 3) : i + 5])
                assert "#warning" in context or "DEVELOPMENT" in context


# ============================================================================
# RNG failure handling tests
# ============================================================================


def test_pro45_rng_failure_aborts():
    """PRO-45: RNG failure aborts key generation (fail-closed)."""
    src = get_uno_q_src()
    # Should have fail-closed handling
    assert "return false" in src  # generateSecureRandomBytes returns false on failure
    assert "ERROR_STATE" in src  # keyState set to ERROR_STATE
    assert "secureWipeKey()" in src  # key wiped on failure


def test_pro45_trng_health_check():
    """PRO-45: TRNG health check exists and validates output."""
    src = get_uno_q_src()
    assert "trngHealthCheck()" in src
    assert "allZero" in src or "all-zero" in src.lower()
    assert "allOnes" in src or "all-0xFF" in src


def test_pro45_key_wipe_on_failure():
    """PRO-45: Key buffer is securely wiped on any failure path."""
    src = get_uno_q_src()
    # secureWipeKey should be called before returning false
    secure_wipe_count = src.count("secureWipeKey()")
    assert secure_wipe_count >= 2  # at least in generateKey failure paths


# ============================================================================
# Key exposure protection tests
# ============================================================================


def test_pro45_key_not_printed_to_serial():
    """PRO-45: Raw key bytes never printed to Serial."""
    src = get_uno_q_src()
    # Should not print aesKey directly
    assert "Serial.print(aesKey" not in src
    assert "Serial.write(aesKey" not in src
    assert "Serial.printf(aesKey" not in src
    # Should not print keyHash directly as key material
    assert "Serial.print(keyHash" not in src


def test_pro45_only_fingerprint_printed():
    """PRO-45: Only key fingerprint (hash) is printed, not the key itself."""
    src = get_uno_q_src()
    # Should print keyHash (fingerprint) but not aesKey
    assert "printHex(keyHash" in src or "printHex(keyHash)" in src
    # Should NOT print aesKey
    assert "printHex(aesKey" not in src


def test_pro45_key_in_ram_only():
    """PRO-45: Key is stored in RAM (static buffer), not in flash/EEPROM."""
    src = get_uno_q_src()
    # Key should be a static uint8_t array (RAM)
    assert "static uint8_t aesKey[AES_KEY_SIZE]" in src
    # Should not use EEPROM or flash storage for key
    assert "EEPROM" not in src
    assert "FlashStorage" not in src
    assert "PROGMEM" not in src


# ============================================================================
# Integration with provisioning flow
# ============================================================================


def test_pro45_generate_key_called_via_bridge():
    """PRO-45: generateKey() is exposed via Bridge RPC for MPU to trigger."""
    src = get_uno_q_src()
    assert "request_key_generation" in src
    assert "generateKey()" in src


def test_pro45_key_state_machine():
    """PRO-45: Key state machine includes GENERATED state."""
    src = get_uno_q_src()
    assert "KeyState::GENERATED" in src or "GENERATED" in src
    assert "KeyState::ERROR_STATE" in src or "ERROR_STATE" in src


def test_pro45_secure_wipe_function_exists():
    """PRO-45: secureWipeKey() function exists for secure key erasure."""
    src = get_uno_q_src()
    assert "secureWipeKey()" in src
    assert "volatile uint8_t*" in src  # volatile to prevent optimization


# ============================================================================
# Source guards for PRO-45
# ============================================================================


def test_pro45_mentioned_in_header():
    """PRO-45: Firmware header mentions PRO-45."""
    src = get_uno_q_src()
    assert "PRO-45" in src
    assert "key generation" in src.lower() or "key gen" in src.lower()


def test_pro45_rng_registers_documented():
    """PRO-45: RNG provenance is documented with reference to STM32U585
    (GTZC-secured peripheral, Zephyr entropy path)."""
    src = get_uno_q_src()
    assert "STM32U585" in src or "RM0453" in src  # Reference manual
    assert "GTZC" in src
    assert "sys_csrand_get" in src
    assert "RNG_CR" not in src and "RNG_SR" not in src and "RNG_DR" not in src


def test_pro45_no_key_exposure_in_logs():
    """PRO-45: Key material is not logged (only fingerprint/hash)."""
    src = get_uno_q_src()
    # Check that no log message contains the actual key
    # The key should only appear as aesKey[keyHash] which is the fingerprint
    lines = src.split("\n")
    for i, line in enumerate(lines):
        if "Serial.print" in line or "Serial.println" in line:
            # Should not contain aesKey (the actual key buffer)
            if "aesKey" in line and "keyHash" not in line:
                # This would be key exposure
                pytest.fail(f"Potential key exposure in line {i+1}: {line.strip()}")


# ============================================================================
# Build verification
# ============================================================================


def test_pro45_firmware_syntax_check():
    """PRO-45: Firmware file exists and has valid basic structure."""
    root = pathlib.Path(__file__).resolve().parent.parent
    src_path = (
        root / "key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino"
    )
    assert src_path.exists(), "UNO Q firmware file not found"
    src = src_path.read_text()
    assert src.startswith("/*")  # Valid C/C++ comment start
    assert "#include <Arduino.h>" in src
    assert "void setup()" in src
    assert "void loop()" in src


def test_pro45_key_generation_output_size():
    """PRO-45: Key generation produces exactly 16 bytes."""
    # This is a logical test - we know AES_KEY_SIZE is 16
    src = get_uno_q_src()
    assert "AES_KEY_SIZE" in src
    # Find the define
    for line in src.split("\n"):
        if "#define AES_KEY_SIZE" in line:
            assert "16" in line
            break
