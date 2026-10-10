"""Point-in-time public source adapters with explicit provenance."""

from .api_anything_client import (
    CollectorSupervisor,
    OperationStatus,
    PublicOperationError,
    PublicOperationErrorCode,
    PublicOperationRecordV1,
    PublicOperationResultV1,
)
from .api_anything_registry import (
    PUBLIC_SOURCES as API_ANYTHING_PUBLIC_SOURCES,
)
from .api_anything_registry import (
    create_client,
    intel_evidence_payload,
    known_records,
)
from .registry import PUBLIC_SOURCES as OFFICIAL_PUBLIC_SOURCES
from .registry import PublicSourceV1, register_many
from .sources import (
    PublicEvidenceV1,
    PublicSourceError,
    PublicSourcesClient,
    parse_cftc_cot,
    parse_coinbase_derivatives_open_interest,
    parse_finra_regsho,
    parse_finra_weekly,
    parse_house_ptr_index,
    parse_public_json_rows,
    parse_sec_form4,
    parse_sec_submissions,
    parse_treasury_curve,
)

PUBLIC_SOURCES = register_many(OFFICIAL_PUBLIC_SOURCES, API_ANYTHING_PUBLIC_SOURCES)

__all__ = [
    "API_ANYTHING_PUBLIC_SOURCES",
    "PUBLIC_SOURCES",
    "CollectorSupervisor",
    "OperationStatus",
    "PublicEvidenceV1",
    "PublicOperationError",
    "PublicOperationErrorCode",
    "PublicOperationRecordV1",
    "PublicOperationResultV1",
    "PublicSourceError",
    "PublicSourceV1",
    "PublicSourcesClient",
    "create_client",
    "intel_evidence_payload",
    "known_records",
    "parse_cftc_cot",
    "parse_coinbase_derivatives_open_interest",
    "parse_finra_regsho",
    "parse_finra_weekly",
    "parse_house_ptr_index",
    "parse_public_json_rows",
    "parse_sec_form4",
    "parse_sec_submissions",
    "parse_treasury_curve",
    "register_many",
]
