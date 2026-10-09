// Test-only MetaTrader source fixture.
// It is never compiled, decompiled, installed, or run by an agent.
// The tests pass these bytes opaquely to a fake filesystem.
#property strict

void OnTick()
{
   // Deliberately does not submit orders or access external resources.
}
