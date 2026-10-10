const REQUIRED_FACTS = [
  ["company.legal_name", (config) => config.company?.legal_name?.value,
    (config) => config.company?.legal_name?.owner_confirmation_required === true],
  ["company.formation_state", (config) => config.company?.formation_state],
  ["company.mailing_address", (config) => config.company?.mailing_address],
  ["company.support_email", (config) => config.company?.support_email],
  ["company.regulatory_status", (config) => config.company?.regulatory_status],
  ["company.web_backend_host", (config) => config.company?.web_backend_host],
  ["company.domain", (config) => config.company?.domain],
  ["company.effective_date", (config) => config.company?.effective_date],
  ["retention.account_deletion_days", (config) => config.retention?.account_deletion_days],
  ["retention.legal_retention_years", (config) => config.retention?.legal_retention_years],
  ["refund_policy", (config) => config.refund_policy],
  ["billing.cancellation_method", (config) => config.billing?.cancellation_method],
];

const PLACEHOLDER = /^(tbd|todo|n\/?a|none|unknown|pending|xxx+|\?+|-+)$/i;
const VALIDATORS = {
  "company.support_email": (v) => !/^mailto:/i.test(v) && /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(v),
  "company.effective_date": (v) => /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v)),
  "company.domain": (v) => /^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v) && !/\.workers\.dev$/i.test(v),
  "retention.account_deletion_days": (v) => /^[1-9][0-9]{0,2}$/.test(v),
  "retention.legal_retention_years": (v) => /^[1-9][0-9]?$/.test(v),
  "billing.cancellation_method": (v) => v === "email" || v === "portal",
};

export function missingFacts(config) {
  return REQUIRED_FACTS.filter(([path, read, confirmationRequired]) => {
    const value = read(config);
    const validator = VALIDATORS[path];
    return typeof value !== "string" || value.trim() === "" || value.includes("[REQUIRED:")
      || PLACEHOLDER.test(value.trim()) || (validator && !validator(value.trim()))
      || (confirmationRequired?.(config) ?? false);
  }).map(([path]) => path);
}

export function assertSiteFacts(config) {
  const missing = missingFacts(config);
  if (missing.length) {
    const error = new Error(`SITE_FACTS_INCOMPLETE: ${missing.join(", ")}`);
    error.code = "SITE_FACTS_INCOMPLETE";
    error.missing = missing;
    throw error;
  }
}
