"use client";

import { useEffect, useState } from "react";

type View = "detection" | "live" | "alerts" | "investigator";
type Alert = Record<string, any>;
const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function Home() {
  const [view, setView] = useState<View>("detection");
  const [status, setStatus] = useState<Record<string, any>>({ trained: false });
  const [profile, setProfile] = useState<Record<string, any> | null>(null);
  const [training, setTraining] = useState<Record<string, any> | null>(null);
  const [comparison, setComparison] = useState<Record<string, any> | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [useExample, setUseExample] = useState(true);
  const [maxRows, setMaxRows] = useState(1000);
  const [label, setLabel] = useState("");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [question, setQuestion] = useState("What are the model metrics?");
  const [answer, setAnswer] = useState<Record<string, any> | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [interfaces, setInterfaces] = useState<Alert[]>([]);
  const [liveState, setLiveState] = useState<Record<string, any>>({ flows: [], active_flows: [] });
  const [selectedFlow, setSelectedFlow] = useState<Record<string, any> | null>(null);

  useEffect(() => {
    fetch(`${API}/model-status`).then((response) => response.json()).then(setStatus)
      .catch(() => setMessage("Python API is offline."));
  }, []);

  useEffect(() => {
    if (view !== "live") return;
    let active = true;
    const refresh = async () => {
      try {
        const response = await fetch(`${API}/live/status`);
        const data = await response.json();
        if (active && response.ok) setLiveState(data);
      } catch { if (active) setMessage("Could not reach the live network API."); }
    };
    fetch(`${API}/live/interfaces`).then((response) => response.json()).then((data) => {
      if (active && Array.isArray(data)) setInterfaces(data);
    }).catch(() => { if (active) setMessage("Could not discover network interfaces."); });
    refresh();
    const timer = window.setInterval(refresh, 2000);
    return () => { active = false; window.clearInterval(timer); };
  }, [view]);

  async function loadDataset() {
    if (!useExample && !file) {
      setMessage("Choose the CICIDS2017 example or upload a CSV/Parquet file.");
      return;
    }
    setBusy(true); setMessage("");
    const form = new FormData();
    form.append("use_example", String(useExample));
    form.append("max_rows", String(maxRows));
    if (file && !useExample) form.append("file", file);
    try {
      const response = await fetch(`${API}/dataset/load`, { method: "POST", body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Dataset loading failed.");
      setProfile(data);
      const candidates = data.label_candidates ?? [];
      setLabel(candidates.includes("is_attack") ? "is_attack" : candidates[0] ?? "");
      setTraining(null); setComparison(null);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Dataset loading failed.");
    } finally { setBusy(false); }
  }

  async function trainModel() {
    if (!label) { setMessage("Select a label column before training."); return; }
    setBusy(true); setMessage("");
    const form = new FormData();
    form.append("label_column", label); form.append("max_rows", String(maxRows));
    try {
      const response = await fetch(`${API}/train`, { method: "POST", body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Training failed.");
      setTraining(data.training); setComparison(data.comparison);
      setStatus({ trained: true, ...data.training });
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Training failed.");
    } finally { setBusy(false); }
  }

  async function loadAlerts() {
    const response = await fetch(`${API}/live/alerts`);
    const data = await response.json();
    setAlerts(Array.isArray(data) ? data : []);
    setView("alerts");
  }

  async function investigate() {
    setBusy(true);
    try {
      const response = await fetch(`${API}/investigate`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      });
      setAnswer(await response.json());
    } catch { setMessage("Could not reach the Python investigation API."); }
    finally { setBusy(false); }
  }

  async function liveAction(action: "start" | "stop" | "clear", interfaceName?: string) {
    setBusy(true); setMessage("");
    try {
      const form = new FormData();
      if (interfaceName) form.append("interface", interfaceName);
      const response = await fetch(`${API}/live/${action}`, { method: "POST", body: action === "start" ? form : undefined });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Live network action failed.");
      setLiveState(data);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Live network action failed.");
    } finally { setBusy(false); }
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div><div className="eyebrow">TABPFN / SENTINEL</div><h1>Network intelligence, grounded in evidence.</h1></div>
        <div className="system-status"><span><i className={training ? "dot good" : "dot"} />{training ? "Model ready" : "Awaiting model"}</span><span><i className="dot good" />Python API</span><span><i className="dot good" />MCP layer</span></div>
      </header>
      <nav className="nav">
        {(["detection", "live", "alerts", "investigator"] as View[]).map((item) => <button className={view === item ? "nav-item active" : "nav-item"} key={item} onClick={() => item === "alerts" ? loadAlerts() : setView(item)}>{item === "live" ? "Live Network" : item[0].toUpperCase() + item.slice(1)}</button>)}
      </nav>
      {message && <div className="notice">{message}</div>}

      {view === "detection" && <>
        <section className="hero-grid">
          <div className="hero-intro"><div className="eyebrow blue">DATASET ANALYSIS</div><h2>See the signal<br /><em>behind the traffic.</em></h2><p className="lede">Use the CICIDS2017 example or upload your own CSV/Parquet dataset, then train the existing TabPFN, Random Forest, and Logistic Regression pipeline.</p></div>
          <article className="hero-video-card">
            <div className="hero-video"><video autoPlay loop muted playsInline src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260421_072701_f6a01abb-eb30-4559-9d6e-774362defbc3.mp4" /><div className="benefit-video-fade" /></div>
            <div className="hero-video-copy"><span>Know-how and Sectoral Awareness</span></div>
          </article>
          <div className="dataset-card">
            <label className="check-row"><input type="checkbox" checked={useExample} onChange={(event) => { setUseExample(event.target.checked); if (event.target.checked) setFile(null); }} /> Use CICIDS2017 example</label>
            {!useExample && <input className="file-input" type="file" accept=".csv,.parquet" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />}
            <label className="field-label">Maximum rows<input className="number-input" type="number" min={100} step={100} value={maxRows} onChange={(event) => setMaxRows(Number(event.target.value))} /></label>
            <button className="primary-button wide" onClick={loadDataset} disabled={busy}>{busy ? "Loading..." : "Load dataset"}</button>
            {profile && <div className="hero-profile">
              <div className="hero-profile-heading"><span className="eyebrow blue">DATASET READY</span><span className="tag">{profile.sample_rows} rows</span></div>
              <div className="hero-profile-stats"><span>{profile.numeric_features} features</span><span>{profile.missing_cells} missing cells</span></div>
              <label className="field-label">Label column<select value={label} onChange={(event) => setLabel(event.target.value)}>{(profile.label_candidates ?? []).map((item: string) => <option key={item}>{item}</option>)}</select></label>
              <button className="primary-button wide" onClick={trainModel} disabled={busy}>{busy ? "Training TabPFN..." : "Train primary model"}</button>
              <p className="helper">Recommended: <b>is_attack</b></p>
            </div>}
          </div>
        </section>
        {training && <TrainingResults training={training} comparison={comparison} profile={profile} />}
      </>}
      {view === "live" && <LiveNetworkView interfaces={interfaces} state={liveState} busy={busy} selectedFlow={selectedFlow} setSelectedFlow={setSelectedFlow} onAction={liveAction} />}
      {view === "alerts" && <section className="page-section"><div className="eyebrow red">LIVE ALERT REGISTER</div><h2>Activity requiring attention.</h2>{alerts.length ? alerts.map((alert, index) => <AlertRow key={alert.flow_id ?? index} alert={alert} onClick={() => setSelectedAlert(alert)} />) : <Empty text="No live attack alerts detected. Start monitoring and generate traffic." />}{selectedAlert && <Detail alert={selectedAlert} onClose={() => setSelectedAlert(null)} />}</section>}
      {view === "investigator" && <section className="page-section investigator"><div className="eyebrow blue">MCP INVESTIGATOR</div><h2>Ask about the evidence.</h2><p className="lede">Questions are sent to the existing Python investigation layer.</p><div className="question-box"><textarea value={question} onChange={(event) => setQuestion(event.target.value)} /><button className="primary-button" onClick={investigate} disabled={busy}>Investigate</button></div><div className="suggestions">{["What are the model metrics?", "Which features were used?", "Show uncertain predictions.", "Is TabPFN better than Random Forest?"].map((item) => <button key={item} onClick={() => setQuestion(item)}>{item}</button>)}</div>{answer && <pre className="answer">{JSON.stringify(answer, null, 2)}</pre>}</section>}
    </main>
  );
}

function LiveNetworkView({ interfaces, state, busy, selectedFlow, setSelectedFlow, onAction }: { interfaces: Alert[]; state: Record<string, any>; busy: boolean; selectedFlow: Record<string, any> | null; setSelectedFlow: (flow: Record<string, any> | null) => void; onAction: (action: "start" | "stop" | "clear", interfaceName?: string) => void }) {
  const [selectedInterface, setSelectedInterface] = useState("");
  const rows = [...(state.flows ?? []), ...(state.active_flows ?? [])];
  const alerts = rows.filter((row) => row.prediction?.is_attack);
  return <section className="page-section live-page"><div className="eyebrow blue">LIVE NETWORK</div><h2>See traffic as it happens.</h2><div className="live-controls"><select value={selectedInterface} disabled={state.monitoring} onChange={(event) => setSelectedInterface(event.target.value)}><option value="" disabled>Choose network interface</option>{interfaces.map((item) => <option key={item.name} value={item.name}>{item.display_name} ({item.ip_address})</option>)}</select><button className="primary-button" disabled={busy || state.monitoring || !selectedInterface} onClick={() => onAction("start", selectedInterface)}>{state.monitoring ? "Monitoring..." : "Start Monitoring"}</button><button className="secondary-button" disabled={busy || !state.monitoring} onClick={() => onAction("stop")}>Stop</button><button className="secondary-button" disabled={busy} onClick={() => onAction("clear")}>Clear Traffic</button></div><div className="live-metrics"><MetricBox label="Packets" value={state.packets_captured ?? 0} /><MetricBox label="Flows" value={state.flows_detected ?? 0} /><MetricBox label="Analyzed" value={state.flows_analyzed ?? 0} /><MetricBox label="Alerts" value={state.suspicious_flows ?? 0} /></div>{state.last_error && <div className="notice">{state.last_error}</div>}<div className="live-table-panel"><div className="panel-heading"><span className="eyebrow">LIVE ACTIVITY</span><span className="tag">{state.monitoring ? "Monitoring" : "Available"}</span></div>{rows.length ? <div className="live-table"><div className="live-table-row live-table-header"><span>Flow</span><span>Source</span><span>Destination</span><span>Protocol</span><span>Packets</span><span>Bytes</span><span>Prediction</span><span>Confidence</span><span>Status</span></div>{rows.map((row) => <button className={`live-table-row ${row.prediction?.is_attack ? "live-alert" : ""}`} key={row.flow_id} onClick={() => setSelectedFlow(row)}><span>{row.flow_id}</span><span>{row.source}</span><span>{row.destination}</span><span>{row.protocol}</span><span>{row.packet_count}</span><span>{row.bytes}</span><span>{row.prediction?.prediction ?? row.error ?? "—"}</span><span>{row.prediction?.confidence !== undefined ? `${(row.prediction.confidence * 100).toFixed(1)}%` : "—"}</span><span>{row.active ? "Active" : "Completed"}</span></button>)}</div> : <Empty text="No completed flows yet. Browse normally to generate real traffic." />}</div>{selectedFlow && <Detail alert={selectedFlow} onClose={() => setSelectedFlow(null)} />}{alerts.length > 0 && <div className="notice red-notice">{alerts.length} suspicious live flow(s) detected.</div>}</section>;
}

function MetricBox({ label, value }: { label: string; value: string | number }) { return <div><span>{label}</span><strong>{value}</strong></div>; }

function TrainingResults({ training, comparison, profile }: { training: Record<string, any>; comparison: Record<string, any> | null; profile: Record<string, any> | null }) {
  const metrics = training.metrics ?? {};
  const models = (comparison?.comparison ?? {}) as Record<string, Record<string, any>>;
  const columns = (profile?.column_names ?? []) as string[];
  return (
    <section className="results-section">
      <div className="results-heading"><div><div className="eyebrow blue">MODEL RESULTS</div><h3>Analysis columns</h3></div><span className="tag">Training complete</span></div>
      <div className="results-metrics">
        <div><span>Accuracy</span><strong>{metrics.accuracy !== undefined ? `${(metrics.accuracy * 100).toFixed(1)}%` : "—"}</strong></div>
        <div><span>Macro F1</span><strong>{metrics.macro_f1 !== undefined ? metrics.macro_f1.toFixed(3) : "—"}</strong></div>
        <div><span>Macro recall</span><strong>{metrics.macro_recall !== undefined ? metrics.macro_recall.toFixed(3) : "—"}</strong></div>
        <div><span>Rows used</span><strong>{metrics.rows_used ?? "—"}</strong></div>
      </div>
      <div className="results-columns">
        <div className="results-panel">
          <div className="eyebrow">MODEL COMPARISON</div>
          <div className="comparison-table">
            <div className="comparison-header"><span>Model</span><span>Accuracy</span><span>Macro F1</span><span>Recall</span></div>
            {Object.entries(models).map(([name, row]) => <div className="comparison-line" key={name}><strong>{name.replaceAll("_", " ")}</strong><span>{row.accuracy !== undefined ? `${(row.accuracy * 100).toFixed(1)}%` : "—"}</span><span>{row.macro_f1?.toFixed?.(3) ?? "—"}</span><span>{row.macro_recall?.toFixed?.(3) ?? "—"}</span></div>)}
          </div>
        </div>
        <div className="results-panel">
          <div className="eyebrow">DATASET COLUMNS ({columns.length})</div>
          <div className="column-list">{columns.length ? columns.map((column) => <span key={column}>{column}</span>) : <span>No column names returned.</span>}</div>
        </div>
      </div>
    </section>
  );
}

function Empty({ text }: { text: string }) { return <div className="empty">{text}</div>; }
function AlertRow({ alert, onClick }: { alert: Alert; onClick: () => void }) { const prediction = typeof alert.prediction === "object" ? alert.prediction.prediction : alert.prediction ?? alert.__predicted_label__ ?? "Unknown"; const confidence = typeof alert.prediction === "object" ? alert.prediction.confidence : alert.confidence ?? alert.__confidence__; return <button className="alert-row" onClick={onClick}><span className="risk-mark" /><span><strong>{prediction}</strong><small>{alert.source ?? `Flow ${alert.flow_id ?? alert.sample_id ?? alert.record_index ?? "—"}`}</small></span><span className="alert-value">{confidence !== undefined ? `${(confidence * 100).toFixed(1)}%` : "Review"}</span><span>→</span></button>; }
function Detail({ alert, onClose }: { alert: Alert; onClose: () => void }) { return <div className="detail panel"><div className="panel-heading"><span className="eyebrow red">EVIDENCE</span><button className="text-button" onClick={onClose}>Close</button></div><pre className="data-block">{JSON.stringify(alert, null, 2)}</pre></div>; }
