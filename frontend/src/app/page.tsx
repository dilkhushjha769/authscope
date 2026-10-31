"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ArrowDown, ArrowLeft, ArrowUp, Check, CheckCircle2, Clock3, Copy, FileText, Loader2, Menu, Moon, Plus, Sun, Wifi, WifiOff, X } from "lucide-react";
import { api, openAssessmentStream } from "@/api/client";
import type { AssessmentActivityEvent, AssessmentSummaryResponse } from "@/types/assessment";

type Lifecycle = "CREATED" | "QUEUED" | "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
type PastScan = { id: string; target_url: string; status: string; started_at?: string; confirmed_findings_count?: number; suspicious_results_count?: number };
type Finding = Record<string, unknown>;
const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");
const active = (status: string) => ["CREATED", "QUEUED", "PENDING", "RUNNING"].includes(status.toUpperCase());
const asText = (value: unknown) => typeof value === "string" ? value : "";
const uniqueFindings = (items: Finding[]) => [...new Map(items.map((item, index) => [asText(item.id) || `missing-id-${index}`, item])).values()];
const shortDate = (value?: string) => value ? new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "Recent";

export default function Home() {
  const [target, setTarget] = useState("");
  const [id, setId] = useState("");
  const [status, setStatus] = useState<Lifecycle | "IDLE">("IDLE");
  const [events, setEvents] = useState<AssessmentActivityEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [report, setReport] = useState<AssessmentSummaryResponse | null>(null);
  const [history, setHistory] = useState<PastScan[]>([]);
  const [error, setError] = useState("");
  const [streamError, setStreamError] = useState("");
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [light, setLight] = useState(false);
  const [mobileSidebar, setMobileSidebar] = useState(false);
  const [historyError, setHistoryError] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [copiedFix, setCopiedFix] = useState<string | null>(null);
  const stream = useRef<AbortController | null>(null);
  const seenIds = useRef(new Set<number>());

  const fetchHistory = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/assessments?limit=10`);
      if (!response.ok) throw new Error("History unavailable");
      const items = await response.json() as PastScan[];
      setHistory(items); setHistoryError(false);
    } catch { setHistoryError(true); }
  }, []);

  const finish = useCallback(async (assessmentId: string, terminal?: string) => {
    stream.current?.abort(); setConnected(false);
    try {
      const data = await api.get(assessmentId);
      setReport(data); setFindings(uniqueFindings(data.findings || [])); setEvents(data.events || []);
      const finalStatus = (terminal || data.status).toUpperCase();
      setStatus((finalStatus === "CANCELLED" || finalStatus === "FAILED" ? finalStatus : data.status.toUpperCase()) as Lifecycle);
      void fetchHistory();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load the final assessment."); }
  }, [fetchHistory]);

  const connect = useCallback((assessmentId: string, previous: AssessmentActivityEvent[] = []) => {
    setStreamError("");
    stream.current?.abort();
    const ids = previous.map((event) => Number(event.id)).filter(Number.isFinite);
    seenIds.current = new Set(ids);
    stream.current = openAssessmentStream(assessmentId, Math.max(0, ...ids), (event) => {
      const eventId = Number(event.id);
      if (Number.isFinite(eventId) && seenIds.current.has(eventId)) return;
      if (Number.isFinite(eventId)) seenIds.current.add(eventId);
      setEvents((existing) => [...existing, event]);
      if (event.event_type.toLowerCase().includes("finding")) {
        void api.get(assessmentId).then((data) => setFindings(uniqueFindings(data.findings || []))).catch(() => undefined);
      }
    }, (done) => { void finish(assessmentId, done.status); }, setConnected, setStreamError);
  }, [finish]);

  const loadAssessment = async (assessmentId: string) => {
    try {
      const data = await api.get(assessmentId);
      const nextStatus = data.status.toUpperCase() as Lifecycle;
      setId(data.id); setTarget(data.target_url); setStatus(nextStatus);
      setEvents(data.events || []); setFindings(uniqueFindings(data.findings || [])); setReport(data);
      setMobileSidebar(false); setError("");
      if (active(nextStatus)) connect(data.id, data.events || []);
      else { stream.current?.abort(); setConnected(false); }
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load this assessment."); }
  };

  useEffect(() => {
    const timer = window.setTimeout(() => { void fetchHistory(); }, 0);
    return () => { window.clearTimeout(timer); stream.current?.abort(); };
  }, [fetchHistory]);

  const start = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy || active(status)) return;
    setError("");
    const suppliedTarget = target.trim();
    const normalizedTarget = /^[a-z][a-z\d+.-]*:\/\//i.test(suppliedTarget) ? suppliedTarget : `http://${suppliedTarget}`;
    let parsed: URL;
    try { parsed = new URL(normalizedTarget); } catch { setError("Enter a valid website address, such as localhost:3000."); return; }
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) { setError("Only http:// and https:// website addresses can be assessed."); return; }
    setBusy(true); setEvents([]); setFindings([]); setReport(null); setId(""); setStreamError(""); seenIds.current.clear();
    try {
      const created = await api.start(parsed.toString().replace(/\/$/, ""));
      setTarget(created.target_url);
      setId(created.assessment_id); setStatus(created.status.toUpperCase() as Lifecycle);
      try {
        const data = await api.get(created.assessment_id);
        setReport(data); setEvents(data.events || []); setFindings(uniqueFindings(data.findings || []));
        connect(created.assessment_id, data.events || []);
      } catch { connect(created.assessment_id); }
      setMobileSidebar(false);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Assessment could not be started."); setStatus("IDLE"); }
    finally { setBusy(false); }
  };

  const newAssessment = () => {
    stream.current?.abort(); setConnected(false); setStatus("IDLE"); setId(""); setEvents([]); setFindings([]); setReport(null); setError(""); setStreamError(""); setTarget(""); setSelectedFinding(null); setMobileSidebar(false);
  };

  const cancel = async () => {
    if (!id || !active(status) || !window.confirm("Cancel this running assessment?")) return;
    setBusy(true); setError("");
    try { await api.cancel(id); await finish(id, "CANCELLED"); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Could not cancel the assessment."); }
    finally { setBusy(false); }
  };

  const mainStatus = active(status) ? "In progress" : status === "COMPLETED" ? "Completed" : status === "FAILED" ? "Failed" : status === "CANCELLED" ? "Cancelled" : "";
  const visibleFindings = uniqueFindings(findings);
  const engineCount = (values: string[]) => visibleFindings.filter((finding) => values.includes(asText(finding.validation_status || finding.confirmation_status || finding.status).toUpperCase())).length;
  const fixesCount = visibleFindings.filter((finding) => Boolean(asText(finding.remediation_recommendation || finding.remediation_guidance))).length;

  return <div className={`workspace ${light ? "workspace-light" : ""}`}>
    {mobileSidebar && <button aria-label="Close sidebar backdrop" className="sidebar-backdrop" onClick={() => setMobileSidebar(false)} />}
    <aside className={`sidebar ${mobileSidebar ? "sidebar-open" : ""}`}>
      <div className="brand"><div className="brand-mark">A</div><span>AuthScope</span><button className="mobile-close icon-button" aria-label="Close menu" onClick={() => setMobileSidebar(false)}><X size={17} /></button></div>
      <button className="new-scan" onClick={newAssessment}><Plus size={18} />New scan</button>
      <div className="history-heading">Past scans</div>
      <div className="history-list">
        {history.map((scan) => {
          const scanStatus = scan.status.toUpperCase();
          const count = Number(scan.confirmed_findings_count || 0) + Number(scan.suspicious_results_count || 0);
          const label = scan.target_url ? (() => { try { return new URL(scan.target_url).hostname; } catch { return scan.target_url; } })() : scan.id;
          return <button key={scan.id} className={`history-item ${id === scan.id ? "history-active" : ""}`} onClick={() => void loadAssessment(scan.id)}>
            <span className="history-title">{label}</span><span className="history-meta">{count} {count === 1 ? "finding" : "findings"} · {shortDate(scan.started_at)}</span>
            {active(scanStatus) && <span className="history-live"><i /> Running</span>}
          </button>;
        })}
        {!history.length && <p className="history-empty">{historyError ? "Assessment history is unavailable while the API is offline." : "Your recent scans will appear here."}</p>}
      </div>
      <button className="theme-toggle" onClick={() => setLight((value) => !value)}>{light ? <Moon size={17} /> : <Sun size={17} />}<span>{light ? "Dark mode" : "Light mode"}</span></button>
    </aside>

    <section className="main-area">
      <header className={`topbar ${!id ? "topbar-home" : ""}`}><button className="icon-button mobile-menu" aria-label="Open menu" onClick={() => setMobileSidebar(true)}><Menu size={20} /></button><div className="topbar-title">{id ? "Assessment" : "New scan"}</div>{id && <div className="topbar-actions">{active(status) ? <button className="cancel-button" onClick={() => void cancel()} disabled={busy}>Cancel scan</button> : <button className="subtle-button" onClick={newAssessment}><Plus size={15} />New scan</button>}</div>}</header>
      <main className={`content ${id ? "content-results" : "content-home"}`}>
        {!id ? <div className="welcome">
          <h1>Break it before they do.</h1>
          <p className="welcome-subtitle">AI that tests your app like an attacker would.</p>
          <form className="target-form" onSubmit={start}>
            <div className="target-field"><input aria-label="Website address" type="text" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="http://localhost:3000" required /><button aria-label="Start assessment" type="submit" disabled={busy || !target.trim()}>{busy ? <Loader2 className="spin" size={20} /> : <ArrowUp size={21} />}</button></div>
            <p className="input-hint">Enter a full address or a website name. Missing schemes default to http://.</p>
            <p className="scope-note">Only assess websites you own or are authorized to test. ScopeGuard validates the target before requests are sent.</p>
            {error && <p className="error-message" role="alert">{error}</p>}
          </form>
        </div> : <div className="assessment-view">
          <div className="assessment-heading"><button className="back-link" onClick={newAssessment}><ArrowLeft size={16} />New scan</button><div className="assessment-title-row"><div><h1>{target ? (() => { try { return new URL(target).hostname; } catch { return target; } })() : "Assessment"}</h1><p className="assessment-id">{id}</p></div><span className={`status-pill ${active(status) ? "status-running" : `status-${status.toLowerCase()}`}`}>{active(status) ? <Loader2 size={14} className="spin" /> : status === "COMPLETED" ? <CheckCircle2 size={14} /> : <Clock3 size={14} />}{mainStatus}</span></div></div>
          {(error || streamError) && <p className="error-message" role="alert">{error || streamError}{streamError && active(status) && <button className="reconnect-button" onClick={() => connect(id, events)}>Reconnect</button>}</p>}
          <div className="conversation-view">
            <div className="target-bubble"><span>Target website</span><p>{target}</p></div>
            <section className="assistant-thread" aria-label="Assessment conversation">
              <div className="assistant-avatar" aria-hidden="true">A</div>
              <div className="assistant-content">
                <div className="assistant-byline"><strong>AuthScope</strong><span>AI-powered authorized security testing</span></div>
                <p className="assistant-intro">{active(status) ? "Assessment is running. Activity below is streamed from the security engine." : status === "COMPLETED" ? "Assessment complete. Review the returned evidence and findings below." : status === "FAILED" ? "The assessment failed. See the backend status and any recorded activity below." : status === "CANCELLED" ? "Assessment cancelled. The activity recorded before cancellation remains available below." : "Assessment details and backend activity are shown below."}</p>
          <div className="results-grid">
            <section className="panel activity-panel"><div className="panel-title"><span>Agent activity</span><span className="connection-state">{connected ? <><Wifi size={14} />Live connection</> : active(status) ? <><WifiOff size={14} />Reconnecting</> : ""}</span></div><div className="activity-feed">{events.length ? events.map((item, index) => <article className="activity-item" key={`${item.id ?? "event"}-${index}`}><span className="activity-dot" /><div><p>{item.message}</p><small>{item.stage} · {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : ""}</small></div></article>) : <p className="empty-note">Waiting for activity from the assessment engine…</p>}</div></section>
            <section className="panel findings-panel"><div className="panel-title"><span>Findings</span><span className="count-chip">{visibleFindings.length}</span></div>{visibleFindings.length ? <div className="finding-list">{visibleFindings.map((finding, index) => {
              const findingId = asText(finding.id) || String(index); const findingStatus = asText(finding.validation_status || finding.confirmation_status || finding.status || "UNVALIDATED").toUpperCase();
              const title = asText(finding.title || finding.vulnerability_category || finding.vulnerability_type) || "Finding";
              const endpoint = asText(finding.endpoint || finding.target_endpoint); const severity = asText(finding.severity).toUpperCase() || "Unrated";
              const details = (finding.technical_details && typeof finding.technical_details === "object" ? finding.technical_details : {}) as Record<string, unknown>;
              const expanded = selectedFinding === findingId;
              const engineTitle = findingStatus.replaceAll("_", " ");
              const recommendation = asText(finding.remediation_recommendation || finding.remediation_guidance);
              const codeExample = asText(details.suggested_code || finding.suggested_code);
              const rootCause = asText(details.root_cause);
              const impactedUsers = Array.isArray(finding.affected_roles) ? finding.affected_roles.join(", ") : asText(finding.affected_role);
              return <article className="finding-card" key={findingId}>
                <button className="finding-summary" onClick={() => setSelectedFinding(expanded ? null : findingId)}>
                  <span className={`severity-mark severity-${severity.toLowerCase()}`} />
                  <span className="finding-main"><strong>{title}</strong><small>{asText(finding.http_method) || "GET"} {endpoint || "Endpoint not provided"}</small></span>
                  <span className="finding-badges"><i className={`finding-status status-text-${findingStatus.toLowerCase()}`}>{engineTitle}</i><i>{severity}</i></span>
                  <ArrowDown size={16} className={expanded ? "rotate" : ""} />
                </button>
                {expanded && <div className="finding-details">
                  <div className="engine-verdict"><strong>Security engine verdict</strong><span>{engineTitle}</span><small>{asText(finding.classification || finding.access_verdict)}</small></div>
                  <h3>Finding description</h3><p>{asText(finding.impact_explanation || finding.description) || "No description was provided by the backend."}</p>
                  <h3>AI review</h3><div className="ai-unavailable"><strong>AI review was not included in the assessment response.</strong><p>The current API returns the security engine finding and its evidence, but does not return an AI verdict, confidence estimate, reasoning, counter-evidence, or missing-evidence analysis. The engine verdict above remains separate and authoritative.</p></div>
                  <div className="analysis-columns"><div><h3>Evidence supporting the finding</h3>{finding.evidence ? <pre>{JSON.stringify(finding.evidence, null, 2)}</pre> : <p className="missing-source">No evidence object was included in the API response.</p>}</div><div><h3>Evidence against / missing</h3><p className="missing-source">The current response schema does not provide separate counter-evidence or an AI evidence-gap analysis.</p></div></div>
                  <h3>Impact</h3><p>{asText(finding.impact_explanation || finding.description) || "Impact details were not supplied."}</p>{impactedUsers && <p className="detail-secondary">Affected roles: {impactedUsers}</p>}
                  <h3>Root cause</h3><p>{rootCause || "Root-cause analysis was not supplied."}</p>
                  {details.source_file || finding.source_file ? <><h3>Vulnerable source</h3><p>{asText(details.source_file || finding.source_file)}{details.line_numbers || finding.line_numbers ? `:${String(details.line_numbers || finding.line_numbers)}` : ""}</p>{(details.vulnerable_code || finding.vulnerable_code) && <pre>{asText(details.vulnerable_code || finding.vulnerable_code)}</pre>}</> : <p className="missing-source">Source mapping was not supplied for this finding.</p>}
                  <h3>Recommended fix</h3><p>{recommendation || "No remediation recommendation was supplied."}</p>
                  {codeExample && <div className="code-example"><div className="code-caption">Secure code example <button onClick={() => { void navigator.clipboard.writeText(codeExample).then(() => { setCopiedFix(findingId); window.setTimeout(() => setCopiedFix(null), 1800); }); }}><>{copiedFix === findingId ? <Check size={13} /> : <Copy size={13} />}{copiedFix === findingId ? "Copied" : "Copy"}</></button></div><pre><code>{codeExample}</code></pre></div>}
                  <h3>Additional recommendations and fix verification</h3><p className="missing-source">Separate security controls and retesting steps were not supplied in the current finding response.</p>
                  {typeof finding.technical_details === "object" && finding.technical_details !== null && <details><summary>Technical evidence</summary><pre>{JSON.stringify(finding.technical_details, null, 2)}</pre></details>}
                </div>}
              </article>;
            })}</div> : <p className="empty-note">{status === "COMPLETED" ? "No findings were returned for this assessment." : "Verified findings will appear here when reported."}</p>}</section>
          </div>
          {report && !active(status) && <section className="report-panel"><div className="panel-title"><span><FileText size={17} />Final report</span><button className="subtle-button print-button" onClick={() => window.print()}>Print report</button></div><dl className="report-grid">{[["Target", report.target_url], ["Assessment ID", report.id], ["Status", report.status], ["Started", report.started_at], ["Finished", report.completed_at || "Not provided"], ["Endpoints tested", report.endpoints_tested_count], ["Findings detected", visibleFindings.length], ["Engine confirmed", engineCount(["CONFIRMED", "CONFIRMED_RUNTIME_VULNERABILITY"])], ["Suspicious / inconclusive", engineCount(["SUSPICIOUS", "SUSPECTED", "INCONCLUSIVE"])], ["Fix recommendations supplied", fixesCount], ["AI reviewed", "Not reported by API"]].map(([label, value]) => <div key={String(label)}><dt>{label}</dt><dd>{value}</dd></div>)}</dl><div className="report-separation"><strong>Security engine verdicts</strong><p>Counts above use engine finding statuses. They are not AI conclusions.</p></div><div className="report-separation"><strong>AI assessment</strong><p>The current assessment response contains no AI finding-review result.</p></div><div className="report-separation"><strong>Actual evidence and summary</strong>{report.summary_text ? <p className="report-summary">{report.summary_text}</p> : <p>No overall summary was supplied by the backend.</p>}</div>{status === "FAILED" && report.failure_reason && <p className="error-message">{report.failure_reason}</p>}</section>}
              </div>
            </section>
          </div>
        </div>}
      </main>
      {!id && <div className="page-help">Authorized testing only · ScopeGuard validates the target before any assessment begins.</div>}
    </section>
  </div>;
}
