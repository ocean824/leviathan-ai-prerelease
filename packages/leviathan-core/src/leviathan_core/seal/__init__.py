"""Shared identity- and content-bound issuance for kernel results."""

from leviathan_core.seal._registry import Issuer, require, verify
from leviathan_core.seal.digest import MAX_DIGEST_NODES, MAX_DIGEST_NODES_CEILING, digest
from leviathan_core.seal.errors import SealError
from leviathan_core.seal.model import SealedModel

__all__ = [
    "MAX_DIGEST_NODES",
    "MAX_DIGEST_NODES_CEILING",
    "Issuer",
    "SealError",
    "SealedModel",
    "digest",
    "require",
    "verify",
]
