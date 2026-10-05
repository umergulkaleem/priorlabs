# MCP-Powered IDS Investigation Agent

An MCP-powered intrusion-detection investigation agent that uses TabPFN 3.5
to detect attacks, quantify prediction reliability, compare classical
baselines, and let analysts investigate predictions through natural language.

## Architecture

`load dataset -> profile/preprocess -> TabPFN 3.5 -> Random Forest and
Logistic Regression -> evaluation -> reliability -> predictions -> MCP tools
-> evidence-backed investigation`

The primary workflow uses the authenticated `tabpfn-client` 0.6 API. Random
Forest and Logistic Regression are comparison baselines, never silent
substitutes for a failed TabPFN run. The local native TabPFN 9.1 path was
tested but is not used by default because the bundled Windows artifact caused
a native access violation; the client path executes successfully.

## Setup

```powershell
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Put the TabPFN credential in `.env` as `TABPFN_TOKEN`. Never commit `.env`.
Rotate any token that has been exposed outside the local machine.

## CLI

TabPFN is the default model:

```powershell
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe main.py data\processed\cicids2017_clean.parquet --label-column is_attack --model tabpfn --max-rows 1000
```

Use `--label-column Label` for multiclass attack categories. Use a baseline
explicitly for local development without a token:

```powershell
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe main.py data\processed\cicids2017_clean.parquet --label-column is_attack --model random_forest --max-rows 50000
```

Each run writes reproducible metrics and reliability data to
`results/latest_experiment.json`.

## First-run analyst UI

Install the dependencies and start the lightweight local UI:

```powershell
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe -m pip install -r requirements.txt
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe -m streamlit run dashboard.py
```

In the browser:

1. Leave **Use CICIDS2017 example** selected or upload a CSV/Parquet file.
2. Click **Load dataset**.
3. Choose `is_attack` for binary IDS or `Label` for attack categories.
4. Click **Train primary TabPFN model**.
5. Open **Model comparison**, **Reliability**, **Alerts**, and **Investigation**.

The UI is a convenience client over the same `IDSInvestigator` engine exposed
by MCP. The MCP tools remain the integration boundary for Copilot and other
MCP clients.

## Next.js frontend

The existing Streamlit dashboard remains available. A separate Next.js
frontend uses the same Python IDS engine through the thin REST adapter in
`src/api.py`:

```powershell
# Terminal 1: Python API
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe -m uvicorn src.api:app --reload --port 8000

# Terminal 2: Next.js UI
Set-Location frontend
npm install
npm run dev
```

Open `http://localhost:3000`. The frontend only calls Python endpoints;
model, baseline, alert, and investigation logic remains in
`src/ids_agent.py`. Streamlit and the MCP server continue to use their
existing entry points.

## Live Network mode

The dashboard has a separate **Live Network** mode. It discovers interfaces
from Scapy, captures real packets from the selected interface, reconstructs
bidirectional flows in memory, extracts observable CICIDS-compatible numeric
features, and sends completed flows through the already-trained model. It does
not read the dataset, synthesize packets, or fabricate alerts. Train the model
in Dataset Analysis first, then select an interface and click **Start
Monitoring**.

On Windows, install **Npcap** from https://npcap.com/ and enable WinPcap
compatibility. On Linux, use libpcap and grant the process packet-capture
permissions. macOS capture depends on libpcap permissions and may require
granting Terminal or Python network access. Docker does not automatically see
host interfaces: host capture must be granted explicitly (`--network=host` and
the appropriate capture capability on Linux); Windows Docker Desktop normally
requires host-side capture or a separate capture service. Permission failures
are reported instead of being replaced with simulated traffic.

Live MCP tools read the atomic snapshot written by the dashboard:

- `get_live_status()`
- `get_recent_live_flows(limit)`
- `get_recent_live_alerts(limit)`
- `get_live_network_summary()`
- `get_live_flow_details(flow_id)`
- `get_live_prediction_evidence(flow_id)`

The extractor derives packet, byte, duration, timing, direction, and TCP flag
statistics. CICIDS fields that require payload or TCP-window inspection are
explicitly zero-valued when unavailable; random values are never inserted.
Live probabilities should therefore be interpreted with this feature
availability limitation in mind.

### Live TabPFN predictions

Every completed live flow is sent through the trained TabPFN model. There is
no artificial per-session flow limit; stop monitoring when you want to end
capture. Because live predictions can make authenticated remote model
requests, monitor API usage and costs when running for long periods.
Stopping capture discards unfinished flows instead of analyzing them. A
prediction already in progress may finish at the provider, but its result is
ignored after monitoring stops.

The model comparison also reuses the primary validation predictions already
computed during training instead of sending a redundant remote prediction
request.

## MCP server

```powershell
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe -m src.mcp_server
```

### Terminal MCP client

The configured server uses MCP `stdio`, so a terminal client cannot attach to
the already-running VS Code process. Start this client instead; it launches a
separate MCP server process and keeps one coherent MCP session for all commands:

```powershell
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe mcp_cli.py
```

Example terminal session:

```text
ids-mcp> load data\processed\cicids2017_clean.parquet 1000
ids-mcp> train is_attack 1000
ids-mcp> compare
ids-mcp> reliability
ids-mcp> uncertain
ids-mcp> ask Is TabPFN better than Random Forest?
ids-mcp> quit
```

Register that command in the existing MCP client configuration. The server
maintains one in-memory investigation state:

1. dataset loaded
2. profile available
3. model trained
4. evaluation and reliability available
5. prediction and investigation available

Calls made too early return structured errors instead of crashing.

## MCP tools

- `load_intrusion_dataset(path, max_rows)`
- `profile_intrusion_dataset()`
- `train_ids_model(label_column, model_name, max_rows)`
- `evaluate_ids_models()`
- `compare_ids_baselines()`
- `predict_traffic(records)`
- `get_reliability_report()`
- `get_uncertain_predictions(limit)`
- `get_false_positives(limit)`
- `get_false_negatives(limit)`
- `get_high_confidence_errors(limit)`
- `get_high_risk_alerts(limit)`
- `get_model_disagreement(limit)`
- `investigate_sample(sample_id)`
- `feature_analysis()`
- `attack_summary()`
- `investigate_ids(question)`
- `ids_status()`

## Reliability methodology

The system reports predicted probabilities, confidence (maximum class
probability), normalized entropy uncertainty, Brier score, Expected
Calibration Error, confidence-vs-accuracy, and reliability bins. Raw model
probabilities are explicitly labeled **uncalibrated**; they are not called
certainty. Validation samples can be inspected as uncertain predictions,
false positives, false negatives, or high-confidence errors.

## Analyst questions

- “What is the accuracy and false-negative rate?”
- “How reliable are the predictions?”
- “Is TabPFN better than Random Forest?”
- “Show uncertain predictions.”
- “Show false negatives.”
- “Show highly confident mistakes.”
- “Which attacks are hardest for TabPFN to detect?”
- “Why was sample 42 classified as malicious?”
- “Which features matter?”

The investigation responses are generated from the current MCP agent state,
metrics, validation rows, and probabilities. Feature explanations are
importance/evidence summaries and are explicitly not causal claims.

## Evaluation and limitations

The default demo uses a deterministic stratified 80/20 split and records the
dataset SHA-256, seed, row/feature counts, preprocessing, model, metrics, and
timestamp. For the bounded 1,000-row binary CICIDS2017 experiment, TabPFN
executed through the authenticated client and achieved 0.985 accuracy,
0.975 macro-F1, ROC-AUC 1.0, PR-AUC 1.0, FPR 0.0, and FNR 0.0769. The exact
baseline and calibration values are in `results/latest_experiment.json`.

Small samples make rare-class metrics unstable. Multiclass labels do not have
a single binary FPR/FNR; the system reports per-class precision/recall/F1 and
sets binary-only metrics to `null`. The current preprocessing excludes
`day` and `file` metadata and retains numeric traffic features; it does not
claim causal feature attribution. A production IDS should use time- or
host-separated validation and post-hoc probability calibration on a separate
calibration split.
