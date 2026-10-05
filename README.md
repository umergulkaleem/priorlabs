# TabPFN Sentinel

## Real network traffic. AI detection. Evidence-based investigation.

TabPFN Sentinel is a local intrusion-detection platform that turns **real
packets from a physical Wi-Fi/Ethernet interface** into explainable security
alerts.

It connects the complete security story:

```text
Real packets
  -> reconstructed network flows
  -> CICIDS-compatible features
  -> TabPFN attack prediction
  -> risk evidence and alert
  -> Next.js dashboard
  -> natural-language MCP investigation
```

This is more than a model demo. A judge can see the traffic arrive, inspect the
flow that was created, review the prediction evidence, and ask the system what
happened.

---

## Why this can win

### 1. It connects AI to the real world

The primary live path uses packets captured from a real network interface. It
does not depend on a fake alert to claim detection.

### 2. It is evidence-first

Every live prediction can be connected to:

- flow ID;
- source and destination;
- source and destination ports;
- protocol;
- packet and byte counts;
- attack probability;
- confidence and uncertainty;
- model evidence;
- baseline model agreement.

### 3. It is explainable through conversation

The MCP investigator lets an analyst ask:

```text
What just happened on my network?
Which connection is highest risk?
Why was flow 17 flagged?
Which port was attacked?
Do the baseline models agree?
```

Answers are grounded in the actual persisted flow and prediction evidence, not
hardcoded incident text.

### 4. It is honest about uncertainty

TabPFN is compared with Random Forest and Logistic Regression. The UI exposes
attack probability, confidence, uncertainty, and disagreement instead of
pretending that every prediction is certain.

### 5. It has a safe demo mode

The project includes a clearly labelled simulated alert so the dashboard and
MCP experience can be demonstrated reliably. Simulated data is marked with
`simulation: true`; it is never presented as proof of packet capture.

---

## The hackathon demo

Use two machines that you own or are authorized to test.

1. Start the API and dashboard on **Machine A**.
2. Train the model using the CICIDS2017-derived dataset.
3. Select Machine A's physical Wi-Fi/Ethernet interface.
4. Start **Live Network** monitoring.
5. From **Machine B**, generate a short, bounded connection pattern against
   Machine B's private IP address.
6. Show packet counters increasing and a real flow being reconstructed.
7. Open the alert and show the TabPFN prediction and evidence.
8. Ask the MCP investigator: `What just happened on my network?`
9. Ask: `Why was this flow flagged?` and `Which port was attacked?`

The strongest claim is precise:

> This authorized traffic was captured, reconstructed as a flow, scored by the
> trained model, and either generated an alert or was recorded as a false
> negative.

Do not scan the public internet or third-party systems. Keep the test private,
short, bounded, and non-destructive.

---

## Run locally on Windows

### Requirements

- Windows with Python 3.13
- Node.js and npm
- Npcap with WinPcap compatibility enabled
- A TabPFN token for the primary model

### Install

```powershell
Set-Location C:\Users\Me\Desktop\Hackathon\priorlabs
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set the token in `.env`:

```text
TABPFN_TOKEN=your-token
```

Never commit `.env` or expose the token in screenshots.

### Start the backend

In Terminal 1:

```powershell
Set-Location C:\Users\Me\Desktop\Hackathon\priorlabs
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe -m uvicorn src.api:app --reload --port 8000
```

Check that it is running:

```powershell
Invoke-WebRequest http://localhost:8000/health
```

### Start the dashboard

In Terminal 2:

```powershell
Set-Location C:\Users\Me\Desktop\Hackathon\priorlabs\frontend
npm install
npm run dev
```

Open <http://localhost:3000>.

### Start the standalone MCP server

Optional, for an MCP client or terminal investigation:

```powershell
Set-Location C:\Users\Me\Desktop\Hackathon\priorlabs
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe -m src.mcp_server
```

---

## Dashboard workflow

1. **Dataset Analysis** — load the example dataset and select `is_attack`.
2. **Train** — train TabPFN and compare the baseline models.
3. **Held-out JSON Test** — classify one attack and one benign validation
   record that were not used for training.
4. **Live Network** — capture real packets and reconstruct flows.
5. **Alerts** — inspect flows classified as attacks.
6. **Investigator** — ask natural-language questions about the live evidence.

The simulated attack button is useful for rehearsing the final three screens.
For a genuine detection claim, use a flow with `simulation: false` and real
interface packet counters.

---

## Architecture

```text
Physical NIC
    |
    v
Scapy capture -> flow reconstruction -> feature extraction
    |
    v
FastAPI + TabPFN + Random Forest + Logistic Regression
    |                         |
    v                         v
Next.js dashboard       live_state.json
                              |
                              v
                    MCP evidence investigation
```

Key files:

- [`src/live_network.py`](src/live_network.py) — packet capture, flows, and
  live features.
- [`src/ids_agent.py`](src/ids_agent.py) — training, prediction, evaluation,
  and reliability analysis.
- [`src/api.py`](src/api.py) — FastAPI endpoints.
- [`src/mcp_server.py`](src/mcp_server.py) — MCP tools and live investigation.
- [`frontend/app/page.tsx`](frontend/app/page.tsx) — Next.js dashboard.

---

## Important model semantics

For binary detection:

```text
0 = BENIGN
1 = ATTACK
```

- `probabilities["1"]` is the attack-class probability.
- `confidence` is the highest class probability, not automatically attack
  probability.
- `uncertainty` is reported separately.
- A live flow appears in Alerts when `prediction.is_attack` is true.
- Probabilities are model outputs, not calibrated certainty.

The live extractor uses only observed traffic. Some full CICIDS fields require
payload, TCP-window, or bulk-transfer inspection and are explicitly represented
as unavailable values rather than fabricated data.

---

## Offline evaluation

```powershell
C:\Users\Me\AppData\Local\Microsoft\WindowsApps\python3.13.exe main.py `
  data\processed\cicids2017_clean.parquet `
  --label-column is_attack --model tabpfn --max-rows 1000
```

Results are saved to
[`results/latest_experiment.json`](results/latest_experiment.json). Offline
metrics are useful for model evaluation, but they do not guarantee live
performance because local traffic can differ from CICIDS2017 feature
distributions.

---

## Responsible testing

Only capture and generate traffic on systems and networks you own or are
authorized to test. A captured-but-benign prediction must be recorded as a
false negative, not hidden. That honesty is part of the product's value:
TabPFN Sentinel shows both the alert and the evidence needed to improve it.
