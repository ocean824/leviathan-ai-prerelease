"""LEVIATHAN AI core domain package.

Pure domain logic for the Black Wealth Capital trading organism.
This package must never import FastAPI, database drivers, broker SDKs,
or any other I/O framework — those live in apps/ and adapter packages.

Domain layout mirrors docs/implementation-module-map.md in the source
architecture repo (ORACLE naming retired in favor of LEVIATHAN):

    schemas/     shared typed contracts (Layer-1 canonical objects)
    ingress/     TradingView webhooks, signal intake (adapters bind in apps/)
    state/       session, range, market-state labeling and transitions
    truth/       order-flow, options, event, sentiment validation
    decision/    decision synthesis and capital permission
    risk/        sovereign risk engine — nothing overrides this module
    execution/   paper simulator and broker-routing contracts
    journal/     trade journaling, replay, drift detection
    research/    strategy genome store, RBI validation registry
    knowledge/   document/vault ingestion contracts
    integration/ OMEGA / PRIME / QUANTUM protocol contracts
"""

__version__ = "0.1.0"
