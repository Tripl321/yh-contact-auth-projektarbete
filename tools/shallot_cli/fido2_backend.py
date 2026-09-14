"""Adapterlager för FIDO2-authenticators (proof of concept, ej certifierat).

Simulator/mock används som standard. Fysisk authenticator (t.ex. Pico
Fido på ESP32-S3) ansluts endast explicit via ``CtapHidBackend`` —
aldrig automatiskt. CTAP2-trafik går över USB HID med Yubicos
``fido2``-paket, som importeras lazy så att mock-läget aldrig kräver
det.

Mocken är HMAC-baserad (stdlib) och INTE en säkerhetsmekanism i sig:
den finns för att öva ceremonier, livscykel och fail-closed-regler.
Nycklar deriveras deterministiskt per anrop och sparas aldrig.
"""

from __future__ import annotations

import hashlib
import hmac

MOCK_DOMAIN = b"SHALLOT-FIDO2-MOCK-v1"
MOCK_VERSION = "mock-hmac-sha256-v1"


class BackendUnavailable(Exception):
    """Fysisk authenticator är inte tillgänglig i denna version."""


class DeviceNotFound(Exception):
    """Ingen FIDO2-authenticator hittad över USB HID."""


class DeviceError(Exception):
    """Enhetsfel: urkopplad, timeout, PIN-fel eller CTAP-fel (fail closed)."""


class AuthenticatorBackend:
    """Gränssnitt som varje backend måste uppfylla."""

    name = "base"

    def sign(self, *, credential_id: bytes, signed_data: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, *, credential_id: bytes, signed_data: bytes, signature: bytes) -> bool:
        raise NotImplementedError


def _mock_key(credential_id: bytes) -> bytes:
    """Derivera mock-nyckel per anrop. Sparas aldrig (se modul-docstring)."""
    return hashlib.sha256(MOCK_DOMAIN + bytes(credential_id)).digest()


class MockBackend(AuthenticatorBackend):
    """Deterministisk HMAC-mock. Standardbackend i v1."""

    name = "mock"

    def sign(self, *, credential_id: bytes, signed_data: bytes) -> bytes:
        if not credential_id or not signed_data:
            raise ValueError("credential_id och signed_data krävs")
        return hmac.new(_mock_key(credential_id), bytes(signed_data), hashlib.sha256).digest()

    def verify(self, *, credential_id: bytes, signed_data: bytes, signature: bytes) -> bool:
        if not credential_id or not signed_data or not signature:
            return False
        expected = hmac.new(_mock_key(credential_id), bytes(signed_data), hashlib.sha256).digest()
        return hmac.compare_digest(expected, bytes(signature))


class HwBackend(AuthenticatorBackend):
    """Bakåtkompatibel stub: fysisk authenticator kräver nu explicit bruk.

    Använd :class:`CtapHidBackend` med ``--hardware``. Stubben finns kvar
    så att gammal kod misslyckas tydligt i stället för tyst.
    """

    name = "hardware"

    def sign(self, *, credential_id: bytes, signed_data: bytes) -> bytes:
        raise BackendUnavailable(
            "använd CtapHidBackend med --hardware för fysisk authenticator")

    def verify(self, *, credential_id: bytes, signed_data: bytes, signature: bytes) -> bool:
        raise BackendUnavailable(
            "använd CtapHidBackend med --hardware för fysisk authenticator")


def _require_fido2():
    try:
        import fido2.hid  # noqa: F401
        import fido2.client  # noqa: F401
    except ImportError:
        raise RuntimeError(
            "fido2-paketet saknas — installera med: python3 -m pip install 'fido2>=1.1'") from None


def _prompt_pin(rp_id: str) -> str | None:
    """Be om FIDO2-PIN i terminalen. Tom rad/EOF = avbryt (aldrig gissa)."""
    print("Enheten kräver PIN. Nyflashad enhet har oftast ingen PIN ännu — "
          "avbryt då med tom rad och sätt en PIN först (t.ex. PicoKey App "
          "eller webbläsarens säkerhetsnyckel-inställningar). Gissa inte: "
          "för många fel PIN kan spärra enheten.")
    import getpass
    try:
        pin = getpass.getpass("FIDO2-PIN för %s: " % rp_id)
    except (EOFError, KeyboardInterrupt):
        return None
    return pin or None


class CtapHidBackend(AuthenticatorBackend):
    """Fysisk authenticator över CTAP2/USB HID (t.ex. Pico Fido @ ESP32-S3).

    Rör aldrig USB i konstruktorn — enheten öppnas först per operation,
    och endast när CLI:t körs med explicit ``--hardware``. För tester kan
    ``device_finder`` och ``client_factory`` injiceras (ingen fysisk
    enhet i testsuiten).
    """

    name = "hardware"

    def __init__(self, *, device_finder=None, client_factory=None):
        self._device_finder = device_finder
        self._client_factory = client_factory

    def sign(self, *, credential_id: bytes, signed_data: bytes) -> bytes:
        raise DeviceError(
            "CTAP-backendet signerar endast via enhetsceremoni "
            "(register/authenticate) — aldrig server-side")

    def verify(self, *, credential_id: bytes, signed_data: bytes, signature: bytes) -> bool:
        raise DeviceError(
            "CTAP-backendet verifierar endast via RP-verifiering "
            "mot lagrad publik nyckel — aldrig server-side")

    def list_devices(self) -> list:
        """Lista anslutna CTAP-enheter (skrivfritt). Tom lista om inga finns."""
        _require_fido2()
        from fido2.hid import CtapHidDevice
        try:
            return list(CtapHidDevice.list_devices())
        except Exception as e:
            raise DeviceError("kunde inte enumerera USB HID-enheter: %s" % e) from None

    def describe_devices(self) -> list:
        """Beskriv anslutna enheter utan att öppna ceremonier. Stänger handtag."""
        infos = []
        for dev in self.list_devices():
            try:
                infos.append({
                    "product": str(getattr(dev, "product_name", "?") or "?"),
                    "serial": str(getattr(dev, "serial_number", "") or ""),
                    "version": str(getattr(dev, "version", "") or ""),
                })
            finally:
                try:
                    dev.close()
                except Exception:
                    pass
        return infos

    def _client(self, origin: str):
        _require_fido2()
        from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction

        class TerminalInteraction(UserInteraction):
            def prompt_up(self):
                print("Rör vid authenticatorns knapp…")

            def request_pin(self, permissions, rp_id):
                return _prompt_pin(rp_id)

        if self._device_finder is not None:
            device = self._device_finder()
        else:
            found = self.list_devices()
            device = found[0] if found else None
        if device is None:
            raise DeviceNotFound(
                "ingen FIDO2-authenticator hittad — anslut enheten (t.ex. Pico Fido) via USB")
        if self._client_factory is not None:
            return self._client_factory(device)
        return Fido2Client(device, DefaultClientDataCollector(origin),
                           user_interaction=TerminalInteraction())

    @staticmethod
    def _map_error(e: Exception, what: str) -> DeviceError:
        from fido2.client import ClientError
        from fido2.ctap import CtapError
        cause = getattr(e, "cause", None) or e
        code = getattr(cause, "code", None)
        if code == CtapError.ERR.PIN_BLOCKED:
            return DeviceError("PIN spärrad på enheten (fabriksåterställning krävs)")
        if code in (CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_NOT_SET,
                    CtapError.ERR.PIN_AUTH_BLOCKED, CtapError.ERR.PIN_AUTH_INVALID):
            return DeviceError("fel/saknad PIN — %s avbruten" % what)
        if code in (CtapError.ERR.ACTION_TIMEOUT, CtapError.ERR.USER_ACTION_TIMEOUT,
                    CtapError.ERR.KEEPALIVE_CANCEL, CtapError.ERR.NOT_ALLOWED):
            return DeviceError("ingen bekräftelse på enheten i tid — %s avbruten" % what)
        if code in (CtapError.ERR.NO_CREDENTIALS, CtapError.ERR.CREDENTIAL_EXCLUDED):
            return DeviceError("enheten har ingen credential för detta RP — %s avbruten" % what)
        if isinstance(e, ClientError) and e.code == ClientError.ERR.TIMEOUT:
            return DeviceError("timeout mot enheten — %s avbruten" % what)
        return DeviceError("%s misslyckades: %s" % (what, e))

    def register(self, *, origin: str, rp_id: str, rp_name: str, user_id: str,
                 challenge: bytes, user_verification: str = "preferred") -> dict:
        """Kör makeCredential på enheten. Returnerar råa attesteringsbytes."""
        from fido2.webauthn import (AttestationConveyancePreference,
                                    AuthenticatorSelectionCriteria,
                                    PublicKeyCredentialCreationOptions,
                                    PublicKeyCredentialParameters,
                                    PublicKeyCredentialRpEntity,
                                    PublicKeyCredentialUserEntity,
                                    UserVerificationRequirement)
        from fido2.client import ClientError
        client = self._client(origin)
        options = PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(id=rp_id, name=rp_name),
            user=PublicKeyCredentialUserEntity(id=user_id.encode(), name=user_id,
                                               display_name=user_id),
            challenge=bytes(challenge),
            pub_key_cred_params=[PublicKeyCredentialParameters(type="public-key", alg=-7)],
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement(user_verification)),
            attestation=AttestationConveyancePreference.DIRECT,
        )
        try:
            result = client.make_credential(options)
        except ClientError as e:
            raise self._map_error(e, "registrering") from None
        except Exception as e:
            raise DeviceError("registrering misslyckades: %s" % e) from None
        resp = result.response
        return {"attestation_object": bytes(resp.attestation_object),
                "client_data_json": bytes(resp.client_data)}

    def authenticate(self, *, origin: str, rp_id: str, challenge: bytes,
                     credential_id: bytes,
                     user_verification: str = "preferred") -> dict:
        """Kör getAssertion på enheten. Returnerar råa assertionsbytes."""
        from fido2.webauthn import (PublicKeyCredentialDescriptor,
                                    PublicKeyCredentialRequestOptions,
                                    UserVerificationRequirement)
        from fido2.client import ClientError
        client = self._client(origin)
        options = PublicKeyCredentialRequestOptions(
            challenge=bytes(challenge),
            rp_id=rp_id,
            allow_credentials=[PublicKeyCredentialDescriptor(
                type="public-key", id=bytes(credential_id))],
            user_verification=UserVerificationRequirement(user_verification),
        )
        try:
            result = client.get_assertion(options)
        except ClientError as e:
            raise self._map_error(e, "autentisering") from None
        except Exception as e:
            raise DeviceError("autentisering misslyckades: %s" % e) from None
        resp = result.get_response(0).response
        return {"authenticator_data": bytes(resp.authenticator_data),
                "client_data_json": bytes(resp.client_data),
                "signature": bytes(resp.signature)}


def get_backend(name: str = "mock") -> AuthenticatorBackend:
    """Returnera backend. 'mock' som standard; 'hardware' kräver --hardware vid bruk."""
    if name == "mock":
        return MockBackend()
    if name == "hardware":
        return CtapHidBackend()
    raise ValueError("okänt backend %r (välj: mock|hardware)" % (name,))
