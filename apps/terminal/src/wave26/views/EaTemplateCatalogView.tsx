import { GatewayProvenance } from "../../components/GatewayProvenance";
import { GatewayStateNotice } from "../../components/GatewayStateNotice";
import { PanelCard } from "../../components/PanelCard";
import { errorPanel } from "../../state/panelState";
import type { PanelState } from "../../state/panelState";
import { useGatewaySnapshot } from "../../state/useGatewaySnapshot";
import { OPERATOR_SESSION_UNAVAILABLE, fetchEaTemplates } from "../api/eaTemplates";
import type { EaCatalogReport } from "../api/eaTemplates";

export const SESSION_UNAVAILABLE_TEXT = "operator session unavailable";

function Catalog({ report }: { report: EaCatalogReport }) {
  const rows = [...report.templates].sort((a, b) => a.templateId.localeCompare(b.templateId));
  return (
    <div className="ea-catalog__report">
      <dl aria-label="API-reported catalog identity">
        <dt>Catalog (API-reported)</dt>
        <dd>{report.catalogId}</dd>
        <dt>Version (API-reported)</dt>
        <dd>{report.version}</dd>
        <dt>Catalog digest (API-reported)</dt>
        <dd><code>{report.catalogDigest}</code></dd>
        <dt>Templates listed</dt>
        <dd>{rows.length}</dd>
        {report.unrecognizedCount > 0 && (
          <>
            <dt>Entries not shown</dt>
            <dd>{report.unrecognizedCount} unrecognized</dd>
          </>
        )}
      </dl>
      {rows.length === 0 ? (
        <p>No templates reported.</p>
      ) : (
        <table className="data-table data-table--compact" aria-label="Template catalog entries">
          <thead>
            <tr>
              <th scope="col">TEMPLATE ID</th>
              <th scope="col">BLOCK</th>
              <th scope="col">PLATFORM</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.templateId}>
                <td>{row.templateId}</td>
                <td>{row.blockId}</td>
                <td>{row.platform}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/** A 401 reads as plain text; every other failure keeps its fixed code. */
function describe(panel: PanelState<EaCatalogReport>): PanelState<EaCatalogReport> {
  if (panel.status !== "error") return panel;
  const code = panel.code === OPERATOR_SESSION_UNAVAILABLE ? SESSION_UNAVAILABLE_TEXT : panel.code;
  return errorPanel(panel.source, code, panel.lastSuccess, panel.retry);
}

export function EaTemplateCatalogView() {
  // One hook per pane: each refresh carries its own request token, so an older
  // response that arrives late can never replace a newer one.
  const snapshot = useGatewaySnapshot(fetchEaTemplates);
  const { data } = snapshot;
  // The route defines no source timestamp and the reader drops any, so this panel can
  // only be loading, unavailable or error; it can never be fresh.
  const described = describe(snapshot.panel);
  return (
    <div className="tab-content">
      <section className="panel" aria-label="EA Templates">
        <h2 className="panel__heading">EA Templates</h2>
        <p className="muted">
          Read-only catalog metadata, as reported by the API. This list says nothing about the
          status of any EA.
        </p>
        <PanelCard
          title="Template catalog"
          eyebrow="EA"
          state={described}
          renderData={(report) => <Catalog report={report} />}
        />
        {snapshot.panel.status === "unavailable" && data !== null && (
          <section aria-label="Template catalog: API-reported catalog" className="ea-catalog__unverified">
            <span className="chip chip--warn">UNVERIFIED</span>
            <p>
              API-reported metadata with no source timestamp. The response receipt time below is
              not source time.
            </p>
            <Catalog report={data} />
          </section>
        )}
        <GatewayStateNotice {...snapshot} state={described} />
        <GatewayProvenance {...snapshot} state={described} />
      </section>
    </div>
  );
}
