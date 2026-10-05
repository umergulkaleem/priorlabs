"""MCP surface for the local IDS investigation agent."""

from __future__ import annotations

from typing import Any

from dotenv import load_dotenv

from .ids_agent import IDSAgentError, IDSInvestigator
from .live_network import live_flow, read_live_state

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as error:  # pragma: no cover - exercised only in missing-dependency environments
    raise RuntimeError("Install the 'mcp' dependency to run the IDS MCP server.") from error


load_dotenv()
mcp = FastMCP("IDS Investigation Agent")
agent = IDSInvestigator()

def _run(operation: Any, state_error: str) -> Any:
    try:
        return operation()
    except IDSAgentError as error:
        return {"error": state_error, "message": str(error)}


@mcp.tool()
def load_intrusion_dataset(path: str, max_rows: int = 100_000) -> dict[str, Any]:
    """Profile a CSV or Parquet intrusion-detection dataset before training."""
    return _run(lambda: agent.load_dataset(path, max_rows=max_rows), "dataset_load_failed")


@mcp.tool()
def profile_intrusion_dataset() -> dict[str, Any]:
    """Return the profile for the currently loaded dataset."""
    return _run(agent.current_profile, "dataset_not_loaded")


@mcp.tool()
def train_ids_model(
    label_column: str | None = None,
    model_name: str = "tabpfn",
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """Train TabPFN 3.5 or a strong local baseline and return held-out metrics."""
    return _run(lambda: agent.train(label_column=label_column, model_name=model_name, max_rows=max_rows),
                "model_training_failed")


@mcp.tool()
def evaluate_ids_models() -> dict[str, Any]:
    """Evaluate TabPFN and both baselines on one deterministic held-out split."""
    return _run(agent.compare_baselines, "model_not_trained")


@mcp.tool()
def compare_ids_baselines() -> dict[str, Any]:
    """Compare the trained model with Random Forest and logistic regression."""
    return _run(agent.compare_baselines, "model_not_trained")


@mcp.tool()
def predict_traffic(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Classify traffic records and return confidence, uncertainty, and evidence."""
    return _run(lambda: agent.predict(records), "model_not_trained")


@mcp.tool()
def get_reliability_report() -> dict[str, Any]:
    """Return Brier score, ECE, calibration bins, and confidence accuracy."""
    return _run(agent.reliability_report, "model_not_trained")


@mcp.tool()
def get_uncertain_predictions(limit: int = 25) -> Any:
    """Return validation predictions with the lowest confidence."""
    return _run(lambda: agent.uncertain_predictions(limit), "model_not_trained")


@mcp.tool()
def get_false_positives(limit: int = 25) -> Any:
    """Return benign validation samples incorrectly flagged as attacks."""
    return _run(lambda: agent.false_positives(limit), "model_not_trained")


@mcp.tool()
def get_false_negatives(limit: int = 25) -> Any:
    """Return attack validation samples missed by the model."""
    return _run(lambda: agent.false_negatives(limit), "model_not_trained")


@mcp.tool()
def get_high_confidence_errors(limit: int = 25) -> Any:
    """Return incorrect predictions ranked by confidence."""
    return _run(lambda: agent.high_confidence_errors(limit), "model_not_trained")


@mcp.tool()
def get_high_risk_alerts(limit: int = 25) -> Any:
    """Return alerts ranked by TabPFN evidence, uncertainty, and model disagreement."""
    return _run(lambda: agent.high_risk_alerts(limit), "model_not_trained")


@mcp.tool()
def get_model_disagreement(limit: int = 25) -> Any:
    """Return validation samples where TabPFN and baselines disagree."""
    return _run(lambda: agent.model_disagreement(limit), "models_not_compared")


@mcp.tool()
def investigate_sample(sample_id: int) -> dict[str, Any]:
    """Explain one held-out validation sample using its actual values and probabilities."""
    return _run(lambda: agent.investigate_sample(sample_id), "model_not_trained")


@mcp.tool()
def feature_analysis() -> dict[str, Any]:
    """Return defensible model feature importance information."""
    return _run(agent.feature_analysis, "model_not_trained")


@mcp.tool()
def attack_summary() -> dict[str, Any]:
    """Return per-attack precision, recall, F1, class counts, and hardest attack."""
    return _run(agent.attack_summary, "model_not_trained")


@mcp.tool()
def investigate_ids(question: str) -> dict[str, Any]:
    """Answer an analyst question using the trained model's actual metrics and schema."""
    return _run(lambda: agent.investigate(question), "model_not_trained")


@mcp.tool()
def ids_status() -> dict[str, Any]:
    """Return the current dataset/model state."""
    return agent.status()


@mcp.tool()
def get_live_status() -> dict[str, Any]:
    """Return current real network capture counters and monitor status."""
    return read_live_state()


@mcp.tool()
def get_recent_live_flows(limit: int = 25) -> list[dict[str, Any]]:
    """Return recently completed real network flows and their predictions."""
    state = read_live_state()
    return state.get("flows", [])[:max(0, limit)]


@mcp.tool()
def get_recent_live_alerts(limit: int = 25) -> list[dict[str, Any]]:
    """Return recently completed live flows classified as attacks."""
    state = read_live_state()
    return [
        flow for flow in state.get("flows", [])
        if flow.get("prediction", {}).get("is_attack", False)
    ][:max(0, limit)]


@mcp.tool()
def get_live_network_summary() -> dict[str, Any]:
    """Return an evidence-backed summary of the current live network window."""
    state = read_live_state()
    alerts = [
        flow for flow in state.get("flows", [])
        if flow.get("prediction", {}).get("is_attack", False)
    ]
    return {
        "answer": (
            f"{state.get('flows_analyzed', 0)} flows analyzed and "
            f"{len(alerts)} suspicious flows detected."
        ),
        "status": {key: value for key, value in state.items() if key != "flows"},
        "highest_risk": max(
            alerts,
            key=lambda flow: flow.get("prediction", {}).get("confidence", 0),
            default=None,
        ),
    }


@mcp.tool()
def get_live_flow_details(flow_id: int) -> dict[str, Any]:
    """Return one completed live flow, including its real flow statistics."""
    return live_flow(read_live_state(), flow_id)


@mcp.tool()
def get_live_prediction_evidence(flow_id: int) -> dict[str, Any]:
    """Return the TabPFN and baseline evidence for one live flow."""
    flow = live_flow(read_live_state(), flow_id)
    if flow.get("prediction") is None:
        return {"flow_id": flow_id, "error": flow.get("error", "Flow was not analyzed.")}
    return {
        "flow_id": flow_id,
        "prediction": flow["prediction"],
        "features": flow["features"],
        "source": flow["source"],
        "destination": flow["destination"],
        "protocol": flow["protocol"],
    }


@mcp.tool()
def investigate_live_network(question: str) -> dict[str, Any]:
    """Answer a live-network question using only the persisted capture state."""
    state = read_live_state()
    flows = state.get("flows", [])
    alerts = [flow for flow in flows if flow.get("prediction", {}).get("is_attack", False)]
    uncertain = [
        flow for flow in flows
        if flow.get("prediction", {}).get("uncertainty", 0) >= 0.3
    ]
    highest = max(
        alerts,
        key=lambda flow: flow.get("prediction", {}).get("confidence", 0),
        default=None,
    )
    text = question.lower()
    if "suspicious" in text or "alert" in text:
        answer = f"{len(alerts)} suspicious flows are present in the current live window."
        evidence = alerts
    elif "uncertain" in text:
        answer = f"{len(uncertain)} live flows have elevated prediction uncertainty."
        evidence = uncertain
    elif "highest" in text or "risk" in text or "investigate" in text:
        answer = "No suspicious flow is currently available." if highest is None else (
            f"Flow {highest['flow_id']} is the highest-risk suspicious flow by model confidence."
        )
        evidence = highest
    else:
        answer = (
            f"{state.get('flows_analyzed', 0)} real flows were analyzed on "
            f"{state.get('interface') or 'the selected interface'}; {len(alerts)} were suspicious."
        )
        evidence = {"status": state, "highest_risk": highest}
    return {"question": question, "answer": answer, "evidence": evidence}


if __name__ == "__main__":
    mcp.run()
