"""Independent SEC-003 contract acceptance using synthetic credentials only."""

from __future__ import annotations

import base64
import copy
import gc
import hashlib
import hmac
import json
import pickle
import socket
import urllib.request
import weakref
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from leviathan_core.seal import SealError, verify
from leviathan_core.security.authz_models import TrustedPrincipalV1
from leviathan_core.security.principal_verifier import (
    PrincipalVerificationError,
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerificationCodeV1,
    VerifiedPrincipalV1,
)

FIXTURES = Path(__file__).parent / "fixtures"
KEY_DATA = json.loads((FIXTURES / "sec003_synthetic_rsa.json").read_text(encoding="utf-8"))
PUBLIC_N = int(KEY_DATA["modulus_hex"], 16)
PUBLIC_E = int(KEY_DATA["public_exponent_hex"], 16)
PRIVATE_D = int(KEY_DATA["private_exponent_hex"], 16)
ISSUER = "https://issuer.synthetic.invalid"
AUDIENCE = "leviathan-api"
ORG = "org-acceptance"
PROJECT = "leviathan-ai"
ENV = "staging"
KID = "synthetic-key-v1"
NOW = datetime(2026, 10, 5, 18, 30, tzinfo=UTC)
NOW_SECONDS = int(NOW.timestamp())
PEER_CERT_DER = (FIXTURES / "sec003_synthetic_peer.der").read_bytes()
PEER_THUMBPRINT = (
    base64.urlsafe_b64encode(hashlib.sha256(PEER_CERT_DER).digest()).rstrip(b"=").decode("ascii")
)


class FakeKeySet:
    def __init__(self, keys: dict[tuple[str, str], RSAPublicKeyV1] | None = None) -> None:
        self.keys = (
            keys if keys is not None else {(ISSUER, KID): RSAPublicKeyV1(PUBLIC_N, PUBLIC_E)}
        )
        self.calls: list[tuple[str, str]] = []

    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        self.calls.append((issuer, kid))
        return self.keys.get((issuer, kid))


class FakeRevocations:
    def __init__(self, revoked: set[tuple[str, str]] | None = None) -> None:
        self.revoked = revoked or set()
        self.calls: list[tuple[str, str]] = []

    def is_revoked(self, issuer: str, jti: str) -> bool:
        self.calls.append((issuer, jti))
        return (issuer, jti) in self.revoked


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _segment(value: object) -> str:
    return _b64url(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _sign_rs256(message: bytes) -> bytes:
    digest_info = (
        bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
    )
    size = (PUBLIC_N.bit_length() + 7) // 8
    padding = size - len(digest_info) - 3
    assert padding >= 8
    encoded = b"\x00\x01" + (b"\xff" * padding) + b"\x00" + digest_info
    return pow(int.from_bytes(encoded, "big"), PRIVATE_D, PUBLIC_N).to_bytes(size, "big")


def _claims(**changes: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "org": ORG,
        "sub": "service-acceptance",
        "role": "researcher",
        "scope": ["research:read", "events:read"],
        "env": ENV,
        "jti": "synthetic-jti-001",
        "iat": NOW_SECONDS,
        "nbf": NOW_SECONDS,
        "exp": NOW_SECONDS + 900,
        "venue": "XNAS",
        "portfolio": "paper-portfolio",
        "strategy": "strategy-acceptance",
    }
    claims.update(changes)
    return claims


def _token(
    *,
    claim_changes: dict[str, object] | None = None,
    header_changes: dict[str, object] | None = None,
    raw_claims: bytes | None = None,
) -> str:
    header: dict[str, object] = {"alg": "RS256", "kid": KID, "typ": "JWT"}
    if header_changes:
        header.update(header_changes)
    encoded_header = _segment(header)
    encoded_claims = (
        _b64url(raw_claims)
        if raw_claims is not None
        else _segment(_claims(**(claim_changes or {})))
    )
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64url(_sign_rs256(signing_input))}"


def _verifier(
    *,
    require_mtls: bool = False,
    key_set: FakeKeySet | None = None,
    revocations: FakeRevocations | None = None,
    clock: Any = lambda: NOW,
) -> PrincipalVerifier:
    return PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer=ISSUER,
            audience=AUDIENCE,
            org_id=ORG,
            project_id=PROJECT,
            env=ENV,
            require_mtls=require_mtls,
        ),
        key_set=key_set or FakeKeySet(),
        revocations=revocations or FakeRevocations(),
        clock=clock,
    )


def _assert_rejected(
    call: Any, code: VerificationCodeV1 = VerificationCodeV1.TOKEN_REJECTED
) -> None:
    with pytest.raises(PrincipalVerificationError) as caught:
        call()
    assert caught.value.code is code
    assert caught.value.args == (code.value,)
    assert str(caught.value) == code.value


def _assert_untrusted(verifier: PrincipalVerifier, candidate: object) -> None:
    _assert_rejected(
        lambda: verifier.to_trusted_principal(candidate),
        VerificationCodeV1.PRINCIPAL_UNISSUED,
    )
    _assert_rejected(
        lambda: verifier.to_sec002_claims(candidate),
        VerificationCodeV1.PRINCIPAL_UNISSUED,
    )


def test_valid_synthetic_rs256_token_maps_only_signed_identity() -> None:
    keys = FakeKeySet()
    revocations = FakeRevocations()
    verifier = _verifier(key_set=keys, revocations=revocations)
    verified = verifier.verify(_token())

    assert type(verified) is VerifiedPrincipalV1
    assert verified.issuer == ISSUER
    assert verified.audience == AUDIENCE
    assert verified.org_id == ORG
    assert verified.project_id == PROJECT
    assert verified.subject_id == "service-acceptance"
    assert verified.role == "researcher"
    assert verified.scopes == ("research:read", "events:read")
    assert verified.env == ENV
    assert verified.issued_at_ns == NOW_SECONDS * 1_000_000_000
    assert verified.expires_at_ns == (NOW_SECONDS + 900) * 1_000_000_000
    assert verified.verified_at_ns == int(NOW.timestamp() * 1_000_000_000)
    assert keys.calls == [(ISSUER, KID)]
    assert revocations.calls == [(ISSUER, "synthetic-jti-001")]

    trusted = verifier.to_trusted_principal(verified)
    claims = verifier.to_sec002_claims(verified)
    assert type(trusted) is TrustedPrincipalV1
    assert claims.principal_id == verified.subject_id
    assert claims.project_id == PROJECT
    assert claims.roles == ("researcher",)
    assert trusted.principal_id == verified.subject_id
    assert trusted.project_id == PROJECT
    assert trusted.roles == ("researcher",)
    assert trusted.env == ENV
    assert trusted.venue == "XNAS"
    assert trusted.portfolio == "paper-portfolio"
    assert trusted.strategy == "strategy-acceptance"
    assert trusted.break_glass is False


@pytest.mark.parametrize(
    "claim_changes",
    [
        {"aud": "other-audience"},
        {"iss": "https://attacker.synthetic.invalid"},
        {"org": "other-org"},
        {"org": None},
        {"env": "production"},
        {"sub": None},
        {"role": None},
        {"scope": []},
        {"scope": ["research:read", "research:read"]},
        {"jti": None},
    ],
    ids=[
        "audience",
        "issuer",
        "cross-org",
        "missing-org",
        "environment",
        "missing-subject",
        "missing-role",
        "empty-scope",
        "duplicate-scope",
        "missing-jti",
    ],
)
def test_signed_but_untrusted_claim_context_is_rejected(
    claim_changes: dict[str, object],
) -> None:
    verifier = _verifier()
    _assert_rejected(lambda: verifier.verify(_token(claim_changes=claim_changes)))


def test_tampered_role_or_org_claim_cannot_be_asserted_by_client() -> None:
    verifier = _verifier()
    original = _token()
    header, payload, signature = original.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    decoded["role"] = "admin"
    decoded["org"] = "attacker-org"
    tampered = f"{header}.{_segment(decoded)}.{signature}"
    _assert_rejected(lambda: verifier.verify(tampered))


@pytest.mark.parametrize(
    "header_changes",
    [
        {"alg": "none"},
        {"alg": "HS256"},
        {"alg": "RS384"},
        {"kid": "unknown-key"},
        {"crit": ["b64"]},
        {"b64": False},
    ],
    ids=[
        "none",
        "hmac-confusion",
        "wrong-rsa-algorithm",
        "unknown-key",
        "critical-header",
        "b64-header",
    ],
)
def test_algorithm_and_header_confusion_are_rejected(
    header_changes: dict[str, object],
) -> None:
    verifier = _verifier()
    _assert_rejected(lambda: verifier.verify(_token(header_changes=header_changes)))


def test_hs256_signature_using_public_modulus_is_not_accepted() -> None:
    header = _segment({"alg": "HS256", "kid": KID})
    claims = _segment(_claims())
    signing_input = f"{header}.{claims}".encode("ascii")
    fake_mac = hmac.new(
        PUBLIC_N.to_bytes((PUBLIC_N.bit_length() + 7) // 8, "big"), signing_input, hashlib.sha256
    ).digest()
    _assert_rejected(lambda: _verifier().verify(f"{header}.{claims}.{_b64url(fake_mac)}"))


def test_invalid_signature_and_malformed_compact_serialization_are_rejected() -> None:
    valid = _token()
    header, payload, signature = valid.split(".")
    wrong_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    verifier = _verifier()
    for candidate in (
        f"{header}.{payload}.{wrong_signature}",
        valid + ".extra",
        "not-a-jwt",
        "..",
        f"{header}.{payload}.!",
    ):
        _assert_rejected(lambda candidate=candidate: verifier.verify(candidate))


def test_duplicate_json_claim_names_are_rejected() -> None:
    raw = json.dumps(_claims(), separators=(",", ":")).encode("utf-8")
    duplicated = raw[:-1] + b',"role":"admin"}'
    _assert_rejected(lambda: _verifier().verify(_token(raw_claims=duplicated)))


@pytest.mark.parametrize("field", ["iat", "nbf", "exp"])
def test_boolean_is_never_accepted_as_token_integer(field: str) -> None:
    _assert_rejected(lambda: _verifier().verify(_token(claim_changes={field: True})))


def test_exact_ttl_and_sixty_second_clock_skew_boundaries() -> None:
    verifier = _verifier()
    assert (
        verifier.verify(
            _token(
                claim_changes={
                    "iat": NOW_SECONDS,
                    "nbf": NOW_SECONDS + 60,
                    "exp": NOW_SECONDS + 900,
                }
            )
        ).expires_at_ns
        == (NOW_SECONDS + 900) * 1_000_000_000
    )
    assert (
        verifier.verify(
            _token(
                claim_changes={
                    "iat": NOW_SECONDS - 100,
                    "nbf": NOW_SECONDS - 100,
                    "exp": NOW_SECONDS - 60,
                }
            )
        ).expires_at_ns
        == (NOW_SECONDS - 60) * 1_000_000_000
    )
    _assert_rejected(
        lambda: verifier.verify(
            _token(claim_changes={"iat": NOW_SECONDS, "nbf": NOW_SECONDS, "exp": NOW_SECONDS + 901})
        )
    )


@pytest.mark.parametrize("claim", ["approval", "entitlement", "break_glass"])
def test_authorization_evidence_claims_cannot_be_minted_by_token(
    claim: str,
) -> None:
    verifier = _verifier()
    _assert_rejected(lambda: verifier.verify(_token(claim_changes={claim: True})))
    _assert_rejected(
        lambda: verifier.verify(
            _token(
                claim_changes={
                    "iat": NOW_SECONDS,
                    "nbf": NOW_SECONDS + 61,
                    "exp": NOW_SECONDS + 900,
                }
            )
        )
    )
    _assert_rejected(
        lambda: verifier.verify(
            _token(
                claim_changes={
                    "iat": NOW_SECONDS - 900,
                    "nbf": NOW_SECONDS - 900,
                    "exp": NOW_SECONDS - 61,
                }
            )
        )
    )
    _assert_rejected(
        lambda: verifier.verify(
            _token(
                claim_changes={
                    "iat": NOW_SECONDS + 61,
                    "nbf": NOW_SECONDS,
                    "exp": NOW_SECONDS + 900,
                }
            )
        )
    )


def test_revoked_jti_is_rejected_after_signature_validation() -> None:
    revocations = FakeRevocations({(ISSUER, "synthetic-jti-001")})
    verifier = _verifier(revocations=revocations)
    _assert_rejected(lambda: verifier.verify(_token()))
    assert revocations.calls == [(ISSUER, "synthetic-jti-001")]


def test_required_mtls_and_optional_certificate_confirmation_are_bound() -> None:
    verifier = _verifier(require_mtls=True)
    _assert_rejected(lambda: verifier.verify(_token()))
    _assert_rejected(
        lambda: verifier.verify(
            _token(claim_changes={"cnf": {"x5t#S256": PEER_THUMBPRINT}}),
            peer_certificate_der=b"wrong",
        )
    )
    bound = verifier.verify(
        _token(claim_changes={"cnf": {"x5t#S256": PEER_THUMBPRINT}}),
        peer_certificate_der=PEER_CERT_DER,
    )
    assert bound.certificate_binding == PEER_THUMBPRINT


def test_certificate_confirmation_must_be_exact_and_cannot_be_replayed() -> None:
    verifier = _verifier()
    _assert_rejected(
        lambda: verifier.verify(_token(claim_changes={"cnf": {"x5t#S256": PEER_THUMBPRINT}}))
    )
    verifier = _verifier(require_mtls=True)
    for wrong in (
        {"x5t#S256": PEER_THUMBPRINT, "extra": "x"},
        {"x5t#S256": "A" * 43},
        "not-an-object",
    ):
        _assert_rejected(
            lambda wrong=wrong: verifier.verify(
                _token(claim_changes={"cnf": wrong}),
                peer_certificate_der=PEER_CERT_DER,
            )
        )


def test_invalid_and_oversized_peer_certificate_inputs_fail_closed() -> None:
    verifier = _verifier()
    for peer in (bytearray(b"synthetic"), b"", b"x" * 32769):
        _assert_rejected(lambda peer=peer: verifier.verify(_token(), peer_certificate_der=peer))
    _assert_rejected(lambda: verifier.verify(_token(claim_changes={"cnf": {"x5t#S256": "A" * 43}})))
    _assert_rejected(lambda: verifier.verify("A" * 16385))


def test_invalid_pinned_configuration_fails_with_content_free_config_code() -> None:
    invalid_configs = (
        lambda: RSAPublicKeyV1(PUBLIC_N, 3),
        lambda: TrustedIssuerV1(ISSUER, AUDIENCE, ORG, PROJECT, ENV, require_mtls=1),
    )
    for construct in invalid_configs:
        with pytest.raises(PrincipalVerificationError) as caught:
            construct()
        assert caught.value.code is VerificationCodeV1.CONFIG_INVALID
        assert caught.value.args == ("CONFIG_INVALID",)
        assert str(caught.value) == "CONFIG_INVALID"


def test_trusted_adapter_rejects_wrong_issuer_tag() -> None:
    verifier = _verifier()
    verified = verifier.verify(_token())
    assert verify(verified, "sec003.verified_principal.v1")
    assert not verify(verified, "sec002.authorization.v1")


def test_untrusted_principal_cannot_be_directly_constructed_or_copied() -> None:
    verifier = _verifier()
    verified = verifier.verify(_token())
    fields = verified.model_dump()
    with pytest.raises(PrincipalVerificationError) as caught:
        VerifiedPrincipalV1(**fields)
    assert caught.value.code is VerificationCodeV1.PRINCIPAL_UNISSUED

    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(SealError):
            operation(verified)

    for updates in ({"role": "admin"}, {}):
        try:
            candidate = verified.model_copy(update=updates)
        except SealError:
            continue
        assert candidate is not verified
        _assert_untrusted(verifier, candidate)


def test_model_validation_construct_and_seal_tampering_never_grant_trust() -> None:
    verifier = _verifier()
    verified = verifier.verify(_token())

    try:
        clone = VerifiedPrincipalV1.model_validate(verified)
    except (PrincipalVerificationError, SealError):
        pass
    else:
        assert clone is not verified
        _assert_untrusted(verifier, clone)

    try:
        constructed = VerifiedPrincipalV1.model_construct(**verified.model_dump())
    except (PrincipalVerificationError, SealError):
        pass
    else:
        _assert_untrusted(verifier, constructed)

    object.__setattr__(verified, "role", "admin")
    _assert_untrusted(verifier, verified)


def test_issued_exports_are_guarded_and_instance_method_shadowing_fails_closed() -> None:
    verifier = _verifier()
    verified = verifier.verify(_token())
    assert json.loads(verified.model_dump_json())["role"] == "researcher"
    assert verified.model_dump()["org_id"] == ORG

    verified.__dict__["_require_if_issued"] = lambda: None
    _assert_untrusted(verifier, verified)


def test_fields_set_tampering_cannot_change_issued_export_or_adaptation() -> None:
    verifier = _verifier()
    verified = verifier.verify(_token())
    try:
        object.__setattr__(verified, "__pydantic_fields_set__", {"role"})
    except SealError as error:
        assert error.args == ("SEAL_FORBIDDEN_OPERATION",)
        assert verified.role == "researcher"
        assert json.loads(verified.model_dump_json())["role"] == "researcher"
        assert verifier.to_trusted_principal(verified).roles == ("researcher",)
    else:
        _assert_untrusted(verifier, verified)
        with pytest.raises((PrincipalVerificationError, SealError)):
            verified.model_dump_json()


def test_frozen_model_assignment_and_deletion_are_denied() -> None:
    verified = _verifier().verify(_token())
    with pytest.raises(SealError) as assignment:
        verified.role = "admin"
    with pytest.raises(SealError) as deletion:
        del verified.role
    assert assignment.value.args == ("SEAL_FORBIDDEN_OPERATION",)
    assert deletion.value.args == ("SEAL_FORBIDDEN_OPERATION",)


def test_in_place_model_reentry_and_dict_state_replacement_fail_closed() -> None:
    verifier = _verifier()
    token = _token()
    verified = verifier.verify(token)
    original_role = verified.role

    try:
        BaseModel.__init__(verified, role="admin")
    except (PrincipalVerificationError, SealError):
        pass
    else:
        _assert_untrusted(verifier, verified)
    if verified.role == original_role:
        assert verifier.to_trusted_principal(verified).roles == (original_role,)

    verified2 = verifier.verify(token)
    state = {"__dict__": {**verified2.__dict__, "role": "admin"}}
    try:
        BaseModel.__setstate__(verified2, state)
    except (PrincipalVerificationError, SealError) as error:
        if isinstance(error, SealError):
            assert error.args == ("SEAL_FORBIDDEN_OPERATION",)
        assert verified2.role == original_role
        assert json.loads(verified2.model_dump_json())["role"] == original_role
        assert verifier.to_trusted_principal(verified2).roles == (original_role,)
    else:
        _assert_untrusted(verifier, verified2)
        with pytest.raises((PrincipalVerificationError, SealError)):
            verified2.model_dump_json()


def test_equal_issued_twins_keep_independent_identity_across_gc() -> None:
    verifier = _verifier()
    left = verifier.verify(_token())
    right = verifier.verify(_token())
    assert left.model_dump() == right.model_dump()
    left_ref = weakref.ref(left)
    right_ref = weakref.ref(right)
    del left
    gc.collect()
    assert left_ref() is None
    assert right_ref() is right
    assert verifier.to_trusted_principal(right).principal_id == "service-acceptance"


def test_public_verification_errors_are_content_free_and_ports_are_fake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "SYNTHETIC_TOKEN_CANARY_DO_NOT_ECHO"
    token = _token(claim_changes={"jti": canary})
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload}.{('A' if signature[0] != 'A' else 'B')}{signature[1:]}"
    verifier = _verifier()
    with pytest.raises(PrincipalVerificationError) as caught:
        verifier.verify(tampered)
    error = caught.value
    assert error.code is VerificationCodeV1.TOKEN_REJECTED
    assert error.args == ("TOKEN_REJECTED",)
    assert canary not in str(error)
    assert canary not in repr(error)
    assert canary not in repr(error.args)
    assert error.__cause__ is None
    assert error.__context__ is None or (
        canary not in str(error.__context__) and canary not in repr(error.__context__)
    )

    external_calls: list[str] = []

    def deny_network(*_args: object, **_kwargs: object) -> None:
        external_calls.append("network")
        raise AssertionError("network access is forbidden in SEC-003 acceptance")

    # Re-run a successful verification with outbound socket and URL access poisoned.
    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(urllib.request, "urlopen", deny_network)
    assert verifier.verify(_token()).subject_id == "service-acceptance"
    assert external_calls == []


def test_concurrent_verification_preserves_issued_identity_consistency() -> None:
    verifier = _verifier()
    token = _token()
    with ThreadPoolExecutor(max_workers=8) as pool:
        principals = list(pool.map(lambda _: verifier.verify(token), range(64)))
    assert all(
        verifier.to_trusted_principal(item).principal_id == "service-acceptance"
        for item in principals
    )
    assert len({id(item) for item in principals}) == len(principals)


def test_port_exception_context_never_reveals_port_or_claim_details() -> None:
    secret = "SYNTHETIC_PORT_EXCEPTION_CANARY"

    class ExplodingKeys:
        def get_key(self, _issuer: str, _kid: str) -> RSAPublicKeyV1 | None:
            raise RuntimeError(secret)

    verifier = _verifier(key_set=ExplodingKeys())  # type: ignore[arg-type]
    with pytest.raises(PrincipalVerificationError) as caught:
        verifier.verify(_token())
    error = caught.value
    assert error.code is VerificationCodeV1.TOKEN_REJECTED
    assert str(error) == "TOKEN_REJECTED"
    assert error.args == ("TOKEN_REJECTED",)
    assert error.__cause__ is None
    assert error.__context__ is None or secret not in repr(error.__context__)
