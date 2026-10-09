from __future__ import annotations

from capability_support import issue_test_capability

from leviathan_market_data.live.replay import (
    TrustedProviderCapabilityV1,
    is_trusted_provider_capability_for,
)


class SyntheticProviderPort:
    def __init__(self, provider_id: str) -> None:
        self.provider_id = provider_id


def test_capability_verification_binds_exact_port_and_issued_seal() -> None:
    source = SyntheticProviderPort("provider-a")
    same_provider = SyntheticProviderPort("provider-a")
    capability = issue_test_capability(source, source.provider_id)

    assert is_trusted_provider_capability_for(capability, source)
    assert not is_trusted_provider_capability_for(capability, same_provider)

    unissued = TrustedProviderCapabilityV1(provider_id="provider-a")
    assert not is_trusted_provider_capability_for(unissued, source)

    object.__setattr__(capability, "provider_id", "provider-b")
    assert not is_trusted_provider_capability_for(capability, source)
