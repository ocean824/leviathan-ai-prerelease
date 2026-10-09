import { TAB_ENTRIES } from "../navigation/registry";
import type { NavigationCode } from "../navigation/registry";

export function WorkspaceTabs({ active, onSelect }: {
  active: NavigationCode; onSelect: (code: NavigationCode) => void;
}) {
  return <nav className="workspace-tabs" role="tablist" aria-label="Workstation functions">
    {TAB_ENTRIES.map((entry) => <button key={entry.code} type="button" role="tab"
      id={`tab-${entry.code}`} aria-controls="active-workspace" aria-selected={active === entry.code}
      aria-label={`${entry.code} ${entry.label}`} title={entry.label}
      className={`workspace-tabs__tab${active === entry.code ? " workspace-tabs__tab--active" : ""}`}
      onClick={() => onSelect(entry.code)}>
      <span className="workspace-tabs__code">{entry.code}</span>
      <span className="workspace-tabs__label">{entry.label}</span>
    </button>)}
  </nav>;
}
