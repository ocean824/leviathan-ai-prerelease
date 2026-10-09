"""Memory Domain — trade journaling, replay, drift detection (ORCA).

Phase 6 implementation target. Every completed AND every blocked trade
ends in a TradeJournalRecord; replay fixtures are first-class test
inputs.
"""
