"""Execution Layer — paper simulator, MT5 bridge, direct broker (MEGALODON).

Phase 5 implementation target; paper_sim arrives first (the replay
spine). Every path must pass contracts.assert_intent_is_authorized and
risk.verify_risk_lock before routing anything.
"""
