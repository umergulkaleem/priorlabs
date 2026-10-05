"""Thin REST adapter over the existing IDS investigator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .ids_agent import IDSAgentError, IDSInvestigator
from .live_network import LiveNetworkMonitor, discover_interfaces, live_flow


app = FastAPI(title="TabPFN Sentinel API", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
agent = IDSInvestigator()
live_monitor = LiveNetworkMonitor(agent)
EXAMPLE_DATASET = Path("data/processed/cicids2017_clean.parquet")


def _error(error: Exception, status_code: int = 400) -> dict[str, Any]:
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=status_code,
        content={"error": "ids_request_failed", "message": str(error)},
    )


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "tabpfn-sentinel-api"}


@app.get("/model-status")
def model_status() -> dict[str, Any]:
    return agent.status()


@app.get("/live/interfaces")
def live_interfaces() -> Any:
    try:
        return discover_interfaces()
    except IDSAgentError as error:
        return _error(error)


@app.get("/live/status")
def live_status() -> dict[str, Any]:
    return live_monitor.snapshot()


@app.get("/live/alerts")
def live_alerts(limit: int = 25) -> list[dict[str, Any]]:
    state = live_monitor.snapshot()
    alerts = [
        flow for flow in state.get("flows", [])
        if flow.get("prediction", {}).get("is_attack") is True
    ]
    return alerts[: max(1, min(limit, 100))]


@app.post("/live/start")
def live_start(interface: str = Form(...)) -> Any:
    try:
        live_monitor.start(interface)
        return live_monitor.snapshot()
    except IDSAgentError as error:
        return _error(error)


@app.post("/live/stop")
def live_stop() -> dict[str, Any]:
    live_monitor.stop()
    return live_monitor.snapshot()


@app.post("/live/clear")
def live_clear() -> dict[str, Any]:
    live_monitor.clear()
    return live_monitor.snapshot()


@app.get("/live/flow/{flow_id}")
def live_flow_details(flow_id: int) -> Any:
    try:
        return live_flow(live_monitor.snapshot(), flow_id)
    except IDSAgentError as error:
        return _error(error)


@app.post("/dataset/load")
async def load_dataset(
    file: UploadFile | None = File(default=None),
    use_example: bool = Form(default=False),
    max_rows: int = Form(default=1000),
) -> Any:
    try:
        if use_example:
            path = EXAMPLE_DATASET
        elif file is not None:
            suffix = Path(file.filename or "").suffix.lower()
            if suffix not in {".csv", ".parquet"}:
                return _error(IDSAgentError("Only CSV and Parquet files are supported."))
            path = Path("results") / f"api_upload{suffix}"
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(await file.read())
        else:
            return _error(IDSAgentError("Choose the CICIDS2017 example or upload a CSV/Parquet file."))
        return agent.load_dataset(str(path), max_rows=max(100, min(max_rows, 100_000)))
    except (IDSAgentError, OSError) as error:
        return _error(error)


@app.post("/train")
def train(
    label_column: str | None = Form(default=None),
    max_rows: int = Form(default=1000),
) -> Any:
    try:
        training = agent.train(label_column=label_column, model_name="tabpfn", max_rows=max_rows)
        comparison = agent.compare_baselines()
        return {"training": training, "comparison": comparison}
    except IDSAgentError as error:
        return _error(error)


@app.post("/analyze")
async def analyze(
    file: UploadFile | None = File(default=None),
    use_example: bool = Form(default=False),
    label_column: str | None = Form(default=None),
    max_rows: int = Form(default=1000),
) -> Any:
    profile = await load_dataset(file=file, use_example=use_example, max_rows=max_rows)
    if not isinstance(profile, dict) or "label_candidates" not in profile:
        return profile
    training = train(label_column=label_column, max_rows=max_rows)
    if not isinstance(training, dict) or "training" not in training:
        return training
    return {"profile": profile, **training}


@app.get("/alerts")
def alerts(limit: int = 25) -> Any:
    try:
        return agent.high_risk_alerts(max(1, min(limit, 100)))
    except IDSAgentError as error:
        return _error(error)


@app.get("/investigation/sample/{sample_id}")
def sample_investigation(sample_id: int) -> Any:
    try:
        return agent.investigate_sample(sample_id)
    except IDSAgentError as error:
        return _error(error)


@app.post("/investigate")
def investigate(payload: dict[str, str]) -> Any:
    question = payload.get("question", "").strip()
    if not question:
        return _error(IDSAgentError("A question is required."))
    try:
        return agent.investigate(question)
    except IDSAgentError as error:
        return _error(error)
