"""Local authentication boundary for the desktop-hosted API (AUTH-MW-001)."""

from .chart_stream_tickets import (
    ChartStreamScopeV1,
    ChartStreamTicketError,
    ChartStreamTicketStore,
)
from .operator_principal import (
    ALLOWED_ENVS,
    DEFAULT_ROLES,
    PROFILE_TAG,
    LocalOperatorProfileV1,
    OperatorAuthError,
    OperatorPrincipalMiddleware,
    make_local_operator_profile,
    require_local_operator_profile,
)

__all__ = [
    "ALLOWED_ENVS",
    "DEFAULT_ROLES",
    "PROFILE_TAG",
    "ChartStreamScopeV1",
    "ChartStreamTicketError",
    "ChartStreamTicketStore",
    "LocalOperatorProfileV1",
    "OperatorAuthError",
    "OperatorPrincipalMiddleware",
    "make_local_operator_profile",
    "require_local_operator_profile",
]
