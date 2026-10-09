import { useEffect, useRef, useState } from "react";
import { REGISTRY } from "../navigation/registry";
import { parseCommand } from "../navigation/commands";
import type { ParsedCommand } from "../navigation/commands";

export type TabCode = import("../navigation/registry").NavigationCode;
type Suggestion = { label: string; value: string; detail: string; disabled?: boolean };
const SYNTAX: Suggestion[] = [
  { label: "/tab <code>", value: "/tab ", detail: "Open a workstation function" },
  { label: "/sym <ticker>", value: "/sym ", detail: "Set symbol context" },
  { label: "/filter <key=val>", value: "/filter ", detail: "Filter local fixture records" },
  { label: "/help", value: "/help", detail: "Open command directory" },
  { label: "/omega <cmd>", value: "/omega ", detail: "ØMEGA bridge unavailable", disabled: true },
];

function suggestionsFor(value: string): Suggestion[] {
  const query = value.trim().toUpperCase();
  if (!query) return [];
  if (query.startsWith("/")) {
    if (query.startsWith("/TAB ")) {
      const codeQuery = query.slice(5).trim();
      return REGISTRY.filter((entry) => entry.code.includes(codeQuery)).map((entry) => ({
        label: entry.code, value: `/tab ${entry.code}`, detail: entry.label,
      }));
    }
    return SYNTAX.filter((item) => item.label.toUpperCase().startsWith(query) || query === "/");
  }
  return REGISTRY.filter((entry) => entry.code.includes(query) || entry.label.toUpperCase().includes(query))
    .map((entry) => ({ label: entry.code, value: entry.code, detail: entry.label }));
}

export function CommandBar({ onCommand }: { onCommand: (command: ParsedCommand) => void }) {
  const [value, setValue] = useState("");
  const [hint, setHint] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState(0);
  const [selectionMoved, setSelectionMoved] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const suggestions = open ? suggestionsFor(value) : [];

  useEffect(() => {
    inputRef.current?.focus();
    const onGlobalKey = (event: KeyboardEvent) => {
      const target = event.target instanceof HTMLElement ? event.target : document.activeElement as HTMLElement | null;
      const editable = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target?.isContentEditable;
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault(); inputRef.current?.focus(); setOpen(true);
      } else if (event.key === "/" && !editable && !event.altKey && !event.ctrlKey && !event.metaKey) {
        event.preventDefault(); inputRef.current?.focus(); setValue("/"); setOpen(true);
      }
    };
    window.addEventListener("keydown", onGlobalKey);
    return () => window.removeEventListener("keydown", onGlobalKey);
  }, []);

  function execute(text: string) {
    const result = parseCommand(text);
    if (result.type === "error") { setHint(result.message); setOpen(false); return; }
    if (result.type === "disabled") { setHint(result.reason); setOpen(false); return; }
    onCommand(result); setValue(""); setHint(null); setOpen(false); setSelectionMoved(false);
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown" && suggestions.length) {
      event.preventDefault(); setHighlight((index) => (index + 1) % suggestions.length); setSelectionMoved(true);
    } else if (event.key === "ArrowUp" && suggestions.length) {
      event.preventDefault(); setHighlight((index) => (index - 1 + suggestions.length) % suggestions.length); setSelectionMoved(true);
    } else if (event.key === "Enter") {
      event.preventDefault();
      const selected = suggestions[highlight];
      const parsed = parseCommand(value);
      if (selectionMoved && selected && !selected.disabled && parseCommand(selected.value).type !== "error") execute(selected.value);
      else if (parsed.type !== "error" && parsed.type !== "disabled") execute(value);
      else if (selected && !selected.disabled && parseCommand(selected.value).type !== "error") execute(selected.value);
      else if (selected?.disabled) setHint(selected.detail);
      else execute(value);
    } else if (event.key === "Escape") {
      event.preventDefault(); setValue(""); setHint(null); setOpen(false); setSelectionMoved(false);
    }
  }

  return <div className="command-wrap">
    <div className="command-bar">
      <span className="command-bar__prompt" aria-hidden="true">⌘</span>
      <label className="sr-only" htmlFor="terminal-command">Command</label>
      <input id="terminal-command" ref={inputRef} className="command-bar__input" type="text" value={value}
        aria-label="Command" aria-autocomplete="list" aria-controls="command-suggestions"
        aria-expanded={suggestions.length > 0}
        aria-activedescendant={suggestions.length ? `command-option-${highlight}` : undefined}
        onChange={(event) => { setValue(event.target.value); setHint(null); setOpen(true); setHighlight(0); setSelectionMoved(false); }}
        onKeyDown={handleKeyDown} onFocus={() => setOpen(Boolean(value))}
        placeholder="Type a function or command…" spellCheck={false} autoComplete="off" maxLength={80} />
      <span className="command-bar__shortcut">CTRL / ⌘ + K</span>
    </div>
    {hint && <p className="command-bar__hint" role="alert">{hint}</p>}
    {suggestions.length > 0 && <div id="command-suggestions" className="command-suggestions" role="listbox" aria-label="Command suggestions">
      {suggestions.map((item, index) => <div id={`command-option-${index}`} key={`${item.value}-${index}`}
        className={`command-suggestion${index === highlight ? " command-suggestion--active" : ""}${item.disabled ? " command-suggestion--disabled" : ""}`}
        role="option" aria-selected={index === highlight} aria-disabled={item.disabled || undefined}
        onMouseDown={(event) => event.preventDefault()}
        onClick={() => item.disabled ? setHint(item.detail) : execute(item.value)}>
        <strong>{item.label}</strong><span>{item.detail}</span>
      </div>)}
    </div>}
  </div>;
}
