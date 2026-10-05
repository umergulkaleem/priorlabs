"""First-run Streamlit analyst interface for the IDS investigation workflow."""

from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from src.ids_agent import IDSAgentError, IDSInvestigator
from src.live_network import LiveNetworkMonitor, discover_interfaces, read_live_state, live_flow


load_dotenv(Path(".env"))
st.set_page_config(page_title="TabPFN IDS Investigator", layout="wide")
st.title("TabPFN IDS Investigator")
st.caption("TabPFN detects suspicious traffic; MCP exposes the evidence for analyst investigation.")

if "agent" not in st.session_state:
    st.session_state.agent = IDSInvestigator()
agent: IDSInvestigator = st.session_state.agent
if "live_monitor" not in st.session_state:
    st.session_state.live_monitor = LiveNetworkMonitor(agent)
live_monitor: LiveNetworkMonitor = st.session_state.live_monitor

dataset_mode, live_mode = st.tabs(["Dataset Analysis", "Live Network"])

with dataset_mode:
    with st.sidebar:
        st.header("Dataset Analysis")
        uploaded = st.file_uploader("Upload CSV or Parquet", type=["csv", "parquet"])
        example = st.checkbox("Use CICIDS2017 example", value=True)
        path = str(Path("data/processed/cicids2017_clean.parquet")) if example and not uploaded else None
        max_rows = st.number_input("Maximum rows", min_value=100, value=1000, step=100)
        if st.button("Load dataset", type="primary"):
            try:
                if uploaded is not None:
                    suffix = Path(uploaded.name).suffix
                    destination = Path("results") / f"uploaded_dataset{suffix}"
                    destination.parent.mkdir(exist_ok=True)
                    destination.write_bytes(uploaded.getvalue())
                    path = str(destination)
                if not path:
                    st.error("Choose the example dataset or upload a file.")
                else:
                    st.session_state.profile = agent.load_dataset(path, int(max_rows))
                    st.success("Dataset loaded.")
            except (IDSAgentError, OSError, ValueError) as error:
                st.error(str(error))

    profile = st.session_state.get("profile")
    if profile:
        st.header("Dataset profile")
        st.metric("Rows", profile["sample_rows"])
        st.metric("Numeric features", profile["numeric_features"])
        label_candidates = profile["label_candidates"]
        default_label = "is_attack" if "is_attack" in label_candidates else label_candidates[0]
        label = st.selectbox(
            "Label column",
            label_candidates,
            index=label_candidates.index(default_label),
            help="Use is_attack for a stable binary benign/attack comparison. Rare multiclass labels may not appear in the holdout split.",
        )
        if st.button("Train primary TabPFN model", type="primary"):
            try:
                with st.spinner("Training TabPFN 3.5 and evaluating baselines..."):
                    result = agent.train(label_column=label, model_name="tabpfn", max_rows=int(max_rows))
                    comparison = agent.compare_baselines()
                st.session_state.training = result
                st.session_state.comparison = comparison
            except IDSAgentError as error:
                st.error(str(error))

    if st.session_state.get("training"):
        training = st.session_state.training
        metrics = training["metrics"]
        st.header("TabPFN 3.5 primary result")
        cols = st.columns(5)
        for column, (title, value) in zip(cols, [
            ("Accuracy", metrics["accuracy"]), ("Macro F1", metrics["macro_f1"]),
            ("Attack recall", metrics["macro_recall"]), ("FNR", metrics.get("false_negative_rate")),
            ("Inference seconds", metrics["inference_seconds"]),
        ]):
            column.metric(title, "n/a" if value is None else f"{value:.3f}")
        tab_comparison, tab_reliability, tab_alerts, tab_chat = st.tabs(
            ["Model comparison", "Reliability", "Alerts", "Investigation"]
        )
        with tab_comparison:
            comparison = st.session_state["comparison"]["comparison"]
            comparison_frame = pd.DataFrame(comparison).T.reindex(columns=[
                "accuracy", "macro_precision", "macro_recall", "macro_f1",
                "weighted_f1", "roc_auc", "pr_auc", "false_positive_rate",
                "false_negative_rate", "inference_seconds", "inference_rows",
            ])
            st.dataframe(comparison_frame, use_container_width=True)
            st.info("All models use the same deterministic held-out split.")
            validation_labels = agent.state.validation_rows["__label__"]
            observed_labels = validation_labels.astype(str).nunique()
            expected_labels = len(agent.state.classes)
            if observed_labels < expected_labels:
                st.warning(
                    f"This holdout contains {observed_labels} of {expected_labels} classes. "
                    "Scores may look artificially high because some rare classes are absent. "
                    "For a meaningful attack comparison, train with the is_attack label."
                )
            if agent.state.label_column.lower() == "is_attack":
                st.caption("Binary metrics are reported because is_attack distinguishes benign from attack traffic.")
            else:
                st.caption("ROC-AUC, PR-AUC, FPR, and FNR are unavailable for this multiclass label.")
            if st.button("Show model disagreements"):
                st.json(agent.model_disagreement())
        with tab_reliability:
            st.warning("Probabilities are uncalibrated model outputs, not guaranteed certainty.")
            st.metric("ECE", f"{training['reliability']['ece']:.4f}")
            st.metric("Brier score", f"{training['reliability']['brier_score']:.4f}")
            st.dataframe(pd.DataFrame(training["reliability"]["bins"]), use_container_width=True)
        with tab_alerts:
            if st.button("Rank highest-risk alerts"):
                st.dataframe(pd.DataFrame(agent.high_risk_alerts()), use_container_width=True)
            if st.button("Show uncertain predictions"):
                st.dataframe(pd.DataFrame(agent.uncertain_predictions()), use_container_width=True)
            if st.button("Show false negatives"):
                st.dataframe(pd.DataFrame(agent.false_negatives()), use_container_width=True)
        with tab_chat:
            question = st.text_input("Ask about the trained model")
            if st.button("Investigate") and question:
                try:
                    st.json(agent.investigate(question))
                except IDSAgentError as error:
                    st.error(str(error))
    else:
        st.info("Load the example dataset, select a label, and train TabPFN to begin.")


with live_mode:
    st.header("LIVE NETWORK")
    try:
        interfaces = discover_interfaces()
    except IDSAgentError as error:
        interfaces = []
        st.error(str(error))
    if interfaces:
        labels = [f"{item['display_name']} ({item['ip_address']})" for item in interfaces]
        selected = st.selectbox("Network Interface", labels)
        selected_interface = interfaces[labels.index(selected)]
        st.write(f"IP Address: `{selected_interface['ip_address']}`")
        st.write("Status: **Monitoring**" if live_monitor.monitoring else "Status: **Available**")
        action = "Stop Monitoring" if live_monitor.monitoring else "Start Monitoring"
        if st.button(action, type="primary"):
            try:
                if live_monitor.monitoring:
                    live_monitor.stop()
                else:
                    live_monitor.start(selected_interface["name"])
                st.rerun()
            except IDSAgentError as error:
                st.error(str(error))
        if st.button("Clear Traffic"):
            live_monitor.clear()
            st.success("Live traffic cleared. New traffic will start at Flow #1.")
            st.rerun()
        if st.button("Investigate My Network"):
            state = read_live_state()
            alerts = [flow for flow in state["flows"] if flow.get("prediction", {}).get("is_attack", False)]
            st.info(
                f"{state['flows_analyzed']} flows analyzed, {len(alerts)} suspicious flows. "
                "This summary is sourced from the live MCP state."
            )
            st.json({
                "question": "What is happening on my network?",
                "answer": f"{state['flows_analyzed']} real flows analyzed; {len(alerts)} suspicious flows detected.",
                "highest_risk": max(
                    alerts, key=lambda item: item["prediction"].get("confidence", 0), default=None
                ),
            })

        def render_live_activity() -> None:
            state = read_live_state()
            cols = st.columns(4)
            for column, (title, value) in zip(cols, [
                ("Packets", state["packets_captured"]), ("Flows", state["flows_detected"]),
                ("Analyzed", state["flows_analyzed"]), ("Alerts", state["suspicious_flows"]),
            ]):
                column.metric(title, value)
            st.caption(
                f"Remote TabPFN live predictions: {state.get('live_predictions_used', 0)} "
                "in this monitoring session."
            )
            if state.get("last_error"):
                st.warning(state["last_error"])
            st.subheader("LIVE ACTIVITY")
            rows = []
            for item in state.get("flows", []) + state.get("active_flows", []):
                prediction = item.get("prediction")
                rows.append({
                    "Flow": item["flow_id"], "Source": item["source"], "Destination": item["destination"],
                    "Protocol": item["protocol"], "Packets": item["packet_count"], "Bytes": item["bytes"],
                    "Prediction": prediction.get("prediction") if prediction else item.get("error"),
                    "Confidence": prediction.get("confidence") if prediction else None,
                    "Status": "Active" if item.get("active") else "Completed",
                })
            if rows:
                st.dataframe(pd.DataFrame(rows), use_container_width=True)
                flow_ids = [row["Flow"] for row in rows]
                selected_flow = st.selectbox("Flow investigation", flow_ids)
                st.json(live_flow(state, int(selected_flow)))
            else:
                st.info("No completed flows yet. Browse normally to generate real traffic.")

        fragment = getattr(st, "fragment", None)
        if fragment is not None:
            fragment(run_every="2s")(render_live_activity)()
        else:
            render_live_activity()
