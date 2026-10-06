# TabPFN Sentinel

## Real Network Traffic. AI-Powered Detection. Evidence-Based Investigation.

**Submission for the TabPFN-3.5 Hackathon**

TabPFN Sentinel is a local, AI-powered Intrusion Detection System (IDS) that analyzes **real network traffic captured from a physical Wi-Fi or Ethernet interface**.

It connects the complete security workflow:

```text
Physical Network Interface
        ↓
Real Packet Capture
        ↓
Flow Reconstruction
        ↓
CICIDS-Compatible Features
        ↓
TabPFN Detection
        ↓
Evidence + Confidence
        ↓
Live Dashboard + MCP Investigation
```

The goal is to detect suspicious network behavior, preserve the evidence behind each prediction, and make the result easy to investigate.

---

## Built with TabPFN-3.5

TabPFN is the **primary machine-learning detector** in TabPFN Sentinel.

The project uses the authenticated TabPFN client through `TabPFNClassifier` to train on structured network-traffic data and classify traffic as benign or attack.

```text
CICIDS2017 / Compatible Dataset
              ↓
          TabPFN
              ↓
      Attack Prediction
              ↓
 Confidence + Evidence
```

The trained TabPFN model is also used for live network-flow prediction.

For comparison, the system evaluates the same traffic data with:

* Random Forest
* Logistic Regression

This allows the TabPFN-based approach to be evaluated against conventional tabular ML baselines.

> **Implementation note:** the project uses the TabPFN client as its primary TabPFN-3.5 hackathon model path. The code does not hard-code a provider-side `"3.5"` model-version parameter.

---

## What It Does

TabPFN Sentinel combines:

* Real packet capture using Scapy
* Bidirectional network-flow reconstruction
* CICIDS2017-compatible traffic features
* TabPFN as the primary ML detector
* Random Forest and Logistic Regression baselines
* Live attack/benign predictions
* Confidence and uncertainty information
* Evidence-backed prediction records
* Persistent alerts and investigation data
* Next.js live monitoring dashboard
* MCP tools for programmatic investigation
* Offline evaluation and model comparison
* Simulation mode for demonstrations

---

## Machine Learning Pipeline

The IDS is trained on structured network-traffic data derived from **CICIDS2017**.

Compatible CSV or Parquet datasets can also be used, provided they contain:

* A label column
* Numeric traffic features
* At least two classes
* A compatible feature schema

```text
CICIDS2017 / Compatible Dataset
              ↓
       Data Cleaning
              ↓
      Feature Selection
              ↓
       Train / Validation
              ↓
           TabPFN
              ↓
       Attack Prediction
              ↓
 Evidence + Confidence + Metrics
```

The same trained model can then be used to classify traffic flows captured from a real network interface.

---

## Real Network Traffic Detection

Unlike an offline-only IDS, Sentinel can capture traffic directly from a physical network interface.

The live collector uses Scapy to observe packets and reconstruct flows.

Each flow tracks information such as:

* Source and destination
* Source and destination ports
* Protocol
* Packet counts
* Byte counts
* Forward/backward traffic
* Flow duration
* Packet lengths
* TCP flags
* Inter-arrival timing
* Forward/backward statistics

The collector transforms the flow into a CICIDS-compatible feature record.

```text
Wi-Fi / Ethernet
       ↓
     Scapy
       ↓
 Packet Capture
       ↓
 Flow Reconstruction
       ↓
 Feature Extraction
       ↓
      TabPFN
       ↓
 Attack Probability
       ↓
 Alert / Normal
```

---

## Detection Results

Each prediction contains more than just a class label.

| Output               | Purpose                                           |
| -------------------- | ------------------------------------------------- |
| Prediction           | Predicted traffic class                           |
| Attack Status        | Whether the prediction is classified as an attack |
| Confidence           | Strength of the model prediction                  |
| Class Probabilities  | Probability assigned to each class                |
| Uncertainty          | Prediction uncertainty information                |
| Evidence             | Observed traffic statistics                       |
| Baseline Predictions | Random Forest / Logistic Regression results       |
| Model Agreement      | Whether models agree                              |

This allows an investigator to see **what the model predicted and what traffic characteristics were observed**.

---
## Installation

### Requirements

* Python 3.10+
* Node.js 18+
* Network interface capable of packet capture
* TabPFN authentication token
* Administrative/root privileges may be required for packet capture depending on the operating system

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Install frontend dependencies:

```bash
cd frontend
npm install
cd ..
```

Set the TabPFN authentication token.

Linux/macOS:

```bash
export TABPFN_TOKEN="your_token_here"
```

Windows PowerShell:

```powershell
$env:TABPFN_TOKEN="your_token_here"
```

---

## Run Locally

TabPFN Sentinel can be run locally as three components:

```text
Terminal 1                 Terminal 2                 Terminal 3
───────────                ───────────                ───────────
FastAPI Backend             Next.js Dashboard          MCP Server
     │                            │                         │
     └───────────────┬────────────┘                         │
                     ↓                                      ↓
              TabPFN Sentinel                    AI-assisted investigation
```

### 1. Start the API

From the project root:

```bash
uvicorn src.api:app --reload
```

The API handles:

* Model training
* Traffic prediction
* Live monitoring
* Alert data
* Investigation data

---

### 2. Start the Dashboard

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local address displayed by Next.js.

The dashboard provides:

* Live network flows
* Predictions
* Confidence
* Attack alerts
* Traffic evidence
* Model information
* Investigation results

---

### 3. Start the MCP Server

Open a **third terminal** from the project root:

```bash
python src/mcp_server.py
```

The MCP server exposes the IDS as investigation tools that an MCP-compatible client can call.

Available tools include:

```text
train_ids_model
evaluate_ids_models
compare_ids_baselines
predict_traffic
get_reliability_report
get_high_risk_alerts
get_model_disagreement
investigate_sample
attack_summary
investigate_ids
```

The MCP server is separate from the web API and dashboard. Keep it running while using an MCP-compatible client for investigation.

### Connecting an MCP Client

Configure your MCP client to launch:

```text
Command:
python

Arguments:
src/mcp_server.py
```

Example MCP configuration:

```json
{
  "mcpServers": {
    "tabpfn-sentinel": {
      "command": "python",
      "args": [
        "src/mcp_server.py"
      ]
    }
  }
}
```

Run the MCP server from the **TabPFN Sentinel project root** so it can access the project's Python modules, datasets, and result files.

---

### 4. Train Before Live Investigation

Before live monitoring or meaningful investigation, train the IDS using a compatible dataset.

The normal workflow is:

```text
Terminal 1
FastAPI
   ↓
Train TabPFN
   ↓
Trained Model
   ↓
Live Monitoring
   ↓
Predictions + Evidence
```

The MCP server can then access the IDS functionality for investigation:

```text
MCP Client
     ↓
MCP Server
     ↓
TabPFN Sentinel
     ↓
Predictions / Alerts / Evidence
```


## Evidence-Based Investigation

Sentinel preserves traffic evidence alongside model predictions.

Examples include:

* Flow duration
* Packet counts
* Byte counts
* Packet-rate statistics
* Byte-rate statistics
* Packet-length statistics
* TCP flag activity
* Forward/backward traffic behavior
* Model probabilities
* Baseline predictions

The system therefore connects:

```text
Prediction
    +
Observed Traffic Evidence
    +
Model Output
    ↓
Investigable Alert
```

The evidence describes observed traffic and model behavior. It should not be interpreted as a causal explanation of why an attack occurred.

---

## Model Comparison

TabPFN is evaluated alongside:

* Random Forest
* Logistic Regression

The models use the same deterministic train/validation split so their results can be compared consistently.

The system reports metrics including:

* Accuracy
* Precision
* Recall
* F1
* ROC-AUC where applicable
* Confusion matrix
* Brier score
* Expected Calibration Error
* Reliability information

---

## MCP Investigation

TabPFN Sentinel includes an **MCP server** that exposes the IDS capabilities as tools for programmatic investigation.

Available tools include:

```text
train_ids_model
evaluate_ids_models
compare_ids_baselines
predict_traffic
get_reliability_report
get_high_risk_alerts
get_model_disagreement
investigate_sample
attack_summary
investigate_ids
```

This allows an MCP-compatible client to interact with the trained IDS, inspect predictions, evaluate models, retrieve alerts, and investigate traffic.

### Run the MCP Server

From the project root:

```bash
python src/mcp_server.py
```

The MCP server starts independently from the web dashboard/API.

If your MCP client launches servers through a command configuration, point it to:

```text
python
```

with:

```text
src/mcp_server.py
```

For example, an MCP configuration can use:

```json
{
  "mcpServers": {
    "tabpfn-sentinel": {
      "command": "python",
      "args": [
        "src/mcp_server.py"
      ]
    }
  }
}
```

Run the command from the **TabPFN Sentinel project directory** so the server can access the project modules, datasets, and result files.

### MCP Workflow

```text
MCP Client
    ↓
TabPFN Sentinel MCP Server
    ↓
IDS Tools
    ↓
Training / Prediction / Investigation
    ↓
Results + Evidence
```

For example, an MCP client can use the investigation tools to:

```text
Train the IDS
      ↓
Evaluate TabPFN
      ↓
Compare baselines
      ↓
Find high-risk alerts
      ↓
Inspect model disagreement
      ↓
Investigate individual traffic
```

---

## Live Dashboard

The project includes a Next.js dashboard for monitoring network activity.

The dashboard displays:

* Live network flows
* Source and destination
* Protocol
* Packet counts
* Byte counts
* Prediction
* Confidence
* Attack status
* High-risk alerts
* Model information
* Investigation results

The dashboard makes the detection pipeline visible instead of hiding the ML process behind a single prediction number.

---

## Live Monitoring

Live monitoring requires a trained model.

The basic workflow is:

```text
1. Load a compatible dataset
2. Train the TabPFN model
3. Select a network interface
4. Start live monitoring
5. Capture network flows
6. Generate CICIDS-compatible features
7. Predict with TabPFN
8. Record alerts and evidence
```

Live monitoring uses the already-trained model. It does **not** retrain TabPFN for every captured flow.

---

## Simulation Mode

The project includes a simulation path for demonstrations and testing when live packet capture is unavailable.

Simulated records are explicitly marked as simulation data.

```text
Real Traffic
    ↓
Real packet capture
    ↓
Real reconstructed flows

Simulation
    ↓
Generated test records
    ↓
Explicit simulation markers
```

Simulation is kept separate from real network observations so demonstration data is not presented as genuine captured traffic.

---

## Offline Evaluation

The system can also be used without live packet capture for reproducible model evaluation.

```text
Dataset
   ↓
Train TabPFN
   ↓
Validation Set
   ↓
Predictions
   ↓
Metrics
   ↓
Baseline Comparison
```

This provides a controlled environment for evaluating the ML component before testing it against live traffic.

---

## Reliability and Prediction Semantics

The system reports:

* Attack probability
* Confidence
* Uncertainty
* Brier score
* Expected Calibration Error
* Reliability information

The reported attack probability represents the model's predicted class probability. It should **not** be interpreted as a perfectly calibrated real-world probability that an attack is occurring.

The system therefore exposes reliability information rather than treating model confidence as absolute certainty.

---

## Important Live-Traffic Considerations

The live feature extractor recreates the traffic features that can be reliably derived from lightweight packet-flow observation.

Some CICIDS-style features, including certain TCP window, payload, bulk-transfer, and detailed directional timing features, are difficult to reproduce exactly from lightweight live packet capture.

Where a feature cannot be reliably derived, the implementation uses explicit zero-valued placeholders rather than inventing random measurements.

These should be interpreted as unavailable or approximated features, not necessarily measured zero values.

Therefore:

> Strong offline performance does not automatically guarantee identical performance on live network traffic.

The live system is designed to provide an end-to-end real-traffic testing and investigation pipeline.

---



## Complete Demonstration

A complete demonstration can be performed using:

```text
CICIDS2017-derived training data
              ↓
         Train TabPFN
              ↓
        Evaluate models
              ↓
     Start real capture
              ↓
       Generate traffic
              ↓
    Reconstruct network flow
              ↓
        TabPFN predicts
              ↓
        Alert + Evidence
              ↓
 Dashboard / MCP Investigation
```

This demonstrates the complete path from **training data to real network detection and investigation**.

---

## Technology

### Machine Learning

* TabPFN
* Random Forest
* Logistic Regression
* Scikit-learn

### Network Analysis

* Scapy
* Packet capture
* Bidirectional flow reconstruction
* CICIDS-compatible feature extraction

### Backend

* Python
* FastAPI
* MCP

### Frontend

* Next.js
* React
* Tailwind CSS

### Storage

* JSON-based persistent live state
* Dataset-based offline evaluation

---

## Responsible Testing

TabPFN Sentinel should only be used on networks and systems where you have permission to monitor and test traffic.

For demonstrations involving suspicious or attack-like traffic, use an isolated lab, authorized test environment, or other controlled infrastructure.

The project is designed to demonstrate **defensive network detection and investigation**, not unauthorized exploitation.

---

## Project Status

TabPFN Sentinel currently provides:

* Real packet capture
* Network-flow reconstruction
* CICIDS-compatible feature extraction
* TabPFN-based detection
* Random Forest and Logistic Regression comparison
* Offline model evaluation
* Live prediction
* Evidence persistence
* Reliability analysis
* Live dashboard
* MCP-based investigation
* Simulation support

The central idea is to connect **TabPFN-based tabular inference with real network telemetry**, while keeping predictions, observed traffic evidence, and investigation workflows visible.
