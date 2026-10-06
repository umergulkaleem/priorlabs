"""Core dataset profiling, IDS training, prediction, and investigation logic."""

from __future__ import annotations

import hashlib
from importlib.metadata import PackageNotFoundError, version as package_version
import json
import os
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


class IDSAgentError(RuntimeError):
    """Expected, user-actionable IDS workflow error."""


@dataclass
class TrainingState:
    dataset_path: str
    label_column: str
    feature_columns: list[str]
    classes: list[str]
    model_name: str
    model: Any
    metrics: dict[str, Any]
    profile: dict[str, Any]
    training_rows: pd.DataFrame = field(repr=False)
    validation_rows: pd.DataFrame = field(repr=False)
    validation_predictions: pd.DataFrame = field(repr=False)
    evaluations: dict[str, Any] = field(default_factory=dict)
    reliability: dict[str, Any] = field(default_factory=dict)
    baseline_models: dict[str, Any] = field(default_factory=dict, repr=False)
    baseline_predictions: pd.DataFrame | None = field(default=None, repr=False)


def _json_safe(value: Any) -> Any:
    if isinstance(value, (np.integer, np.floating)):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def _file_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


class IDSInvestigator:
    """Stateful, local-first IDS investigator used by MCP tools and the CLI."""

    def __init__(self) -> None:
        self.state: TrainingState | None = None
        self._dataset: pd.DataFrame | None = None

    @staticmethod
    def _model_details(model_name: str, model: Any) -> dict[str, Any]:
        details: dict[str, Any] = {
            "model": model_name,
            "implementation": f"{type(model).__module__}.{type(model).__name__}",
        }
        if model_name == "tabpfn":
            try:
                details["client_package_version"] = package_version("tabpfn-client")
            except PackageNotFoundError:
                details["client_package_version"] = None
            details["model_version_requested"] = "v3.5"
            details["version_note"] = (
                "v3.5 was explicitly requested from tabpfn-client; "
                "the provider/model artifact version is not independently exposed."
            )
        return details

    def load_dataset(self, path: str, max_rows: int = 100_000) -> dict[str, Any]:
        dataset_path = Path(path).expanduser().resolve()
        if not dataset_path.is_file():
            raise IDSAgentError(f"Dataset does not exist: {dataset_path}")
        if dataset_path.suffix.lower() == ".parquet":
            try:
                import pyarrow.parquet as parquet
                parquet_file = parquet.ParquetFile(dataset_path)
                batches = []
                batch_size = 10_000
                batch_count = max(1, (parquet_file.metadata.num_rows + batch_size - 1) // batch_size)
                selected_count = min(batch_count, max(10, (max_rows + 999) // 1000))
                selected_batches = set(np.linspace(0, batch_count - 1, selected_count, dtype=int))
                per_batch = max(1, (max_rows + selected_count - 1) // selected_count)
                for batch_index, batch in enumerate(parquet_file.iter_batches(batch_size=batch_size)):
                    if batch_index not in selected_batches:
                        continue
                    sampled = batch.to_pandas().sample(
                        min(per_batch, batch.num_rows), random_state=42 + batch_index
                    )
                    batches.append(sampled)
                frame = pd.concat(batches, ignore_index=True).head(max_rows)
            except ImportError as error:
                raise IDSAgentError("Parquet support requires pyarrow. Install requirements.txt.") from error
            except Exception as error:
                raise IDSAgentError(f"Could not stream the Parquet dataset: {error}") from error
        elif dataset_path.suffix.lower() == ".csv":
            frame = pd.read_csv(dataset_path, encoding="latin1", low_memory=False, nrows=max_rows)
        else:
            raise IDSAgentError("Only CSV and Parquet datasets are supported.")
        frame.columns = [str(column).strip() for column in frame.columns]
        frame = frame.replace([np.inf, -np.inf], np.nan)
        frame.attrs["path"] = str(dataset_path)
        self._dataset = frame
        profile = self.profile_dataset(frame)
        profile["path"] = str(dataset_path)
        profile["sample_rows"] = len(frame)
        profile["dataset_sha256"] = _file_sha256(dataset_path)
        return profile

    @staticmethod
    def profile_dataset(frame: pd.DataFrame) -> dict[str, Any]:
        label_candidates = [
            column for column in frame.columns
            if str(column).lower() in {"label", "target", "class", "attack", "is_attack"}
        ]
        numeric = frame.select_dtypes(include=[np.number])
        return _json_safe({
            "rows": len(frame),
            "columns": len(frame.columns),
            "column_names": [str(column) for column in frame.columns],
            "label_candidates": label_candidates,
            "numeric_features": len(numeric.columns),
            "missing_cells": int(frame.isna().sum().sum()),
            "constant_columns": [column for column in frame.columns if frame[column].nunique(dropna=False) <= 1],
            "class_counts": {
                column: frame[column].value_counts(dropna=False).head(20).to_dict()
                for column in label_candidates
            },
        })

    def current_profile(self) -> dict[str, Any]:
        if self._dataset is None:
            raise IDSAgentError("Load a dataset before requesting its profile.")
        profile = self.profile_dataset(self._dataset)
        profile["sample_rows"] = len(self._dataset)
        profile["path"] = self._dataset.attrs.get("path")
        return _json_safe(profile)

    def train(
        self,
        label_column: str | None = None,
        model_name: str = "tabpfn",
        max_rows: int = 100_000,
        test_size: float = 0.2,
    ) -> dict[str, Any]:
        if self._dataset is None:
            raise IDSAgentError("Load a dataset before training.")
        frame = self._dataset.copy()
        if label_column is None:
            candidates = self.profile_dataset(frame)["label_candidates"]
            label_column = candidates[0] if candidates else None
        if not label_column or label_column not in frame.columns:
            raise IDSAgentError("Could not identify a label column. Pass label_column explicitly.")

        y = frame[label_column].astype(str).str.strip()
        valid = y.notna() & (y != "") & (y.str.lower() != "nan")
        frame, y = frame.loc[valid], y.loc[valid]
        excluded = {label_column, "day", "file"}
        features = [column for column in frame.columns if column not in excluded]
        numeric_features = [column for column in features if pd.api.types.is_numeric_dtype(frame[column])]
        if not numeric_features:
            raise IDSAgentError("No numeric traffic features remain after excluding metadata columns.")
        X = frame[numeric_features].apply(pd.to_numeric, errors="coerce")
        if y.nunique() < 2:
            raise IDSAgentError("The selected label has fewer than two classes.")
        if len(frame) > max_rows:
            sample_indices = frame.groupby(y, group_keys=False).apply(
                lambda group: group.sample(min(len(group), max_rows // y.nunique() + 1), random_state=42),
                include_groups=False,
            ).index
            sample_indices = sample_indices[:max_rows]
            X, y, frame = X.loc[sample_indices], y.loc[sample_indices], frame.loc[sample_indices]

        stratify = y if y.value_counts().min() >= 2 else None
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=stratify
        )
        model = self._make_model(model_name)
        model.fit(X_train, y_train)
        inference_started = time.perf_counter()
        probabilities = model.predict_proba(X_test)
        inference_seconds = time.perf_counter() - inference_started
        predictions = model.classes_[np.argmax(probabilities, axis=1)]
        metrics = self._evaluate_predictions(y_test, predictions, probabilities, model, model_name)
        metrics.update({"rows_used": len(frame), "features": len(numeric_features),
                        "train_rows": len(X_train), "test_rows": len(X_test),
                        "inference_seconds": float(inference_seconds)})
        validation_predictions = X_test.copy()
        validation_predictions["__true_label__"] = y_test.to_numpy()
        validation_predictions["__predicted_label__"] = predictions
        validation_predictions["__confidence__"] = probabilities.max(axis=1)
        validation_predictions["__correct__"] = predictions == y_test.to_numpy()
        for index, class_name in enumerate(model.classes_):
            validation_predictions[f"__prob_{class_name}__"] = probabilities[:, index]
        reliability = self._reliability_report(y_test, predictions, probabilities, model.classes_)
        self.state = TrainingState(
            dataset_path=str(Path(self._dataset.attrs.get("path", "")).resolve()),
            label_column=label_column,
            feature_columns=numeric_features,
            classes=metrics["classes"],
            model_name=model_name,
            model=model,
            metrics=_json_safe(metrics),
            profile=self.profile_dataset(frame),
            training_rows=X.assign(**{"__label__": y}),
            validation_rows=X_test.assign(**{"__label__": y_test}),
            validation_predictions=validation_predictions,
            evaluations={model_name: _json_safe(metrics)},
            reliability=reliability,
        )
        result = {
            "primary_model": (
                "TabPFN v3.5 (requested)"
                if model_name == "tabpfn"
                else model_name
            ),
            "model_details": self._model_details(model_name, model),
            "metrics": metrics,
            "reliability": reliability,
            "profile": self.state.profile,
        }
        self._save_experiment(result)
        return _json_safe(result)

    @staticmethod
    def _evaluate_predictions(y_true: pd.Series, predictions: np.ndarray, probabilities: np.ndarray,
                              model: Any, model_name: str) -> dict[str, Any]:
        classes = [str(item) for item in model.classes_]
        matrix = confusion_matrix(y_true, predictions, labels=model.classes_)
        report = classification_report(y_true, predictions, output_dict=True, zero_division=0)
        metrics: dict[str, Any] = {
            "model": model_name,
            "classes": classes,
            "accuracy": float(accuracy_score(y_true, predictions)),
            "macro_precision": float(precision_score(y_true, predictions, average="macro", zero_division=0)),
            "macro_recall": float(recall_score(y_true, predictions, average="macro", zero_division=0)),
            "macro_f1": float(f1_score(y_true, predictions, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_true, predictions, average="weighted", zero_division=0)),
            "classification_report": report,
            "confusion_matrix": matrix.tolist(),
            "confusion_matrix_labels": classes,
            "inference_rows": len(y_true),
        }
        if len(classes) == 2:
            positive = classes[1]
            binary_true = (y_true.astype(str) == positive).astype(int)
            binary_pred = (pd.Series(predictions).astype(str) == positive).astype(int)
            tn, fp, fn, tp = confusion_matrix(binary_true, binary_pred, labels=[0, 1]).ravel()
            metrics.update({
                "roc_auc": float(roc_auc_score(binary_true, probabilities[:, 1])),
                "pr_auc": float(average_precision_score(binary_true, probabilities[:, 1])),
                "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
                "false_positive_rate": float(fp / max(fp + tn, 1)),
                "false_negative_rate": float(fn / max(fn + tp, 1)),
                "attack_recall": float(tp / max(tp + fn, 1)),
            })
        else:
            metrics["roc_auc"] = None
            metrics["pr_auc"] = None
            attack_true = ~y_true.map(lambda value: str(value).strip().upper() == "BENIGN")
            attack_pred = ~pd.Series(predictions).map(lambda value: str(value).strip().upper() == "BENIGN")
            attack_tp = int((attack_true & attack_pred).sum())
            attack_fn = int((attack_true & ~attack_pred).sum())
            metrics["attack_recall"] = float(attack_tp / max(attack_tp + attack_fn, 1))
        return metrics

    @staticmethod
    def _reliability_report(y_true: pd.Series, predictions: np.ndarray, probabilities: np.ndarray,
                            classes: np.ndarray, bins: int = 10) -> dict[str, Any]:
        confidence = probabilities.max(axis=1)
        correct = (predictions == y_true.to_numpy()).astype(float)
        edges = np.linspace(0.0, 1.0, bins + 1)
        reliability_bins = []
        for low, high in zip(edges[:-1], edges[1:]):
            selected = (confidence >= low) & ((confidence < high) if high < 1 else (confidence <= high))
            reliability_bins.append({
                "lower": float(low), "upper": float(high), "count": int(selected.sum()),
                "confidence": float(confidence[selected].mean()) if selected.any() else None,
                "accuracy": float(correct[selected].mean()) if selected.any() else None,
                "gap": float(abs(confidence[selected].mean() - correct[selected].mean())) if selected.any() else None,
            })
        ece = sum(item["gap"] * item["count"] for item in reliability_bins if item["gap"] is not None) / len(y_true)
        if len(classes) == 2:
            positive = (y_true.astype(str) == str(classes[1])).astype(int)
            brier = brier_score_loss(positive, probabilities[:, 1])
        else:
            one_hot = np.zeros_like(probabilities)
            for index, label in enumerate(classes):
                one_hot[:, index] = y_true.astype(str).to_numpy() == str(label)
            brier = float(np.mean(np.sum((probabilities - one_hot) ** 2, axis=1)))
        return _json_safe({
            "probabilities_are_uncalibrated": True,
            "brier_score": float(brier),
            "ece": float(ece),
            "bins": reliability_bins,
            "confidence_accuracy": {
                "mean_confidence": float(confidence.mean()),
                "accuracy": float(correct.mean()),
                "samples": len(correct),
            },
        })

    def _save_experiment(self, result: dict[str, Any]) -> None:
        Path("results").mkdir(exist_ok=True)
        artifact = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "random_seed": 42,
            "dataset": result["profile"],
            "model": result["metrics"],
            "reliability": result["reliability"],
            "preprocessing": {"infinite_values": "NaN", "numeric_coercion": True, "metadata_excluded": ["day", "file"]},
        }
        Path("results/latest_experiment.json").write_text(
            json.dumps(_json_safe(artifact), indent=2), encoding="utf-8"
        )

    def compare_baselines(self) -> dict[str, Any]:
        """Evaluate strong local baselines on the same deterministic split."""
        if self.state is None:
            raise IDSAgentError("Train a model before comparing baselines.")
        rows = self.state.training_rows
        X, y = rows[self.state.feature_columns], rows["__label__"]
        stratify = y if y.value_counts().min() >= 2 else None
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=stratify
        )
        comparison = {self.state.model_name: self.state.metrics}
        for name in ("random_forest", "logistic_regression"):
            if name == self.state.model_name:
                continue
            started = time.perf_counter()
            model = self._make_model(name)
            model.fit(X_train, y_train)
            probabilities = model.predict_proba(X_test)
            predictions = model.classes_[np.argmax(probabilities, axis=1)]
            row = self._evaluate_predictions(y_test, predictions, probabilities, model, name)
            row["inference_seconds"] = float(time.perf_counter() - started)
            comparison[name] = row
        self.state.evaluations = _json_safe(comparison)
        baseline_predictions = pd.DataFrame(index=X_test.index)
        # Reuse the primary predictions already produced during train(). A
        # TabPFN client prediction here would spend another remote request.
        primary_predictions = self.state.validation_predictions.loc[
            X_test.index, "__predicted_label__"
        ]
        baseline_predictions[self.state.model_name] = primary_predictions.to_numpy()
        self.state.baseline_models = {}
        for name in ("random_forest", "logistic_regression"):
            if name == self.state.model_name:
                continue
            model = self._make_model(name)
            model.fit(X_train, y_train)
            self.state.baseline_models[name] = model
            baseline_predictions[name] = model.predict(X_test)
        self.state.baseline_predictions = baseline_predictions
        result = {"primary_model": (
                      "TabPFN v3.5 (requested)"
                      if self.state.model_name == "tabpfn"
                      else self.state.model_name
                  ),
                  "comparison": comparison, "evaluation": "same 80/20 split, random_state=42"}
        self._save_experiment({"profile": self.state.profile, "metrics": comparison,
                               "reliability": self.state.reliability})
        return _json_safe(result)

    def model_disagreement(self, limit: int = 25) -> list[dict[str, Any]]:
        if self.state is None or self.state.baseline_predictions is None:
            raise IDSAgentError("Compare models before requesting prediction disagreement.")
        predictions = self.state.baseline_predictions.copy()
        model_names = list(predictions.columns)
        predictions["agreement_count"] = predictions[model_names].nunique(axis=1)
        selected = predictions[predictions["agreement_count"] > 1].head(limit)
        return _json_safe([
            {
                "sample_id": int(index),
                "predictions": {name: str(row[name]) for name in model_names},
                "disagreement": True,
                "true_label": str(self.state.validation_predictions.loc[index, "__true_label__"]),
                "tabpfn_confidence": float(self.state.validation_predictions.loc[index, "__confidence__"]),
            }
            for index, row in selected.iterrows()
        ])

    def high_risk_alerts(self, limit: int = 25) -> list[dict[str, Any]]:
        if self.state is None:
            raise IDSAgentError("Train the IDS model before requesting alerts.")
        rows = self.state.validation_predictions.copy()
        if self.state.baseline_predictions is not None:
            for name in self.state.baseline_predictions.columns:
                rows[f"__{name}__"] = self.state.baseline_predictions[name]
            model_names = list(self.state.baseline_predictions.columns)
        else:
            model_names = []
        rows["__risk__"] = (
            rows["__confidence__"]
            + (~rows["__correct__"]).astype(float) * 0.25
            + rows.get("__tabpfn__", rows["__predicted_label__"]).map(
                lambda value: 0.15 if not self._is_benign(value) else 0.0
            )
        )
        rows = rows.sort_values(["__risk__", "__confidence__"], ascending=False).head(limit)
        alerts = []
        for index, row in rows.iterrows():
            agreement = {name: str(row[f"__{name}__"]) for name in model_names}
            agrees = len(set(agreement.values())) <= 1 if agreement else None
            alerts.append({
                "sample_id": int(index),
                "predicted_label": str(row["__predicted_label__"]),
                "true_label": str(row["__true_label__"]),
                "risk_score": float(row["__risk__"]),
                "confidence": float(row["__confidence__"]),
                "uncertainty": float(1.0 - row["__confidence__"]),
                "models_agree": agrees,
                "model_predictions": agreement,
                "historically_error_prone": not bool(row["__correct__"]),
                "should_investigate": bool((not row["__correct__"]) or not agrees),
            })
        return _json_safe(alerts)

    def reliability_report(self) -> dict[str, Any]:
        if self.state is None:
            raise IDSAgentError("Train the IDS model before requesting reliability.")
        return _json_safe(self.state.reliability)

    def _cohort(self, kind: str, limit: int = 25) -> list[dict[str, Any]]:
        if self.state is None:
            raise IDSAgentError("Train the IDS model before investigating predictions.")
        rows = self.state.validation_predictions
        if kind == "false_positive":
            selected = rows[rows["__true_label__"].map(self._is_benign) & ~rows["__correct__"]]
        elif kind == "false_negative":
            selected = rows[~rows["__true_label__"].map(self._is_benign) & ~rows["__correct__"]]
        elif kind == "high_confidence_error":
            selected = rows[~rows["__correct__"]].sort_values("__confidence__", ascending=False)
        else:
            selected = rows.sort_values("__confidence__", ascending=True)
        result = []
        for index, row in selected.head(limit).iterrows():
            probabilities = {
                label.removeprefix("__prob_").removesuffix("__"): float(row[label])
                for label in row.index if label.startswith("__prob_")
            }
            result.append({
                "sample_id": int(index), "true_label": str(row["__true_label__"]),
                "predicted_label": str(row["__predicted_label__"]),
                "confidence": float(row["__confidence__"]),
                "uncertainty": float(1.0 - row["__confidence__"]),
                "correct": bool(row["__correct__"]), "probabilities": probabilities,
                "feature_values": _json_safe(row[self.state.feature_columns].head(10).to_dict()),
                "evidence": self._evidence(row[self.state.feature_columns], float(row["__confidence__"])),
            })
        return _json_safe(result)

    def false_positives(self, limit: int = 25) -> list[dict[str, Any]]:
        return self._cohort("false_positive", limit)

    def false_negatives(self, limit: int = 25) -> list[dict[str, Any]]:
        return self._cohort("false_negative", limit)

    def high_confidence_errors(self, limit: int = 25) -> list[dict[str, Any]]:
        return self._cohort("high_confidence_error", limit)

    def uncertain_predictions(self, limit: int = 25) -> list[dict[str, Any]]:
        return self._cohort("uncertain", limit)

    def investigate_sample(self, sample_id: int) -> dict[str, Any]:
        if self.state is None:
            raise IDSAgentError("Train the IDS model before investigating a sample.")
        match = self.state.validation_predictions.loc[
            self.state.validation_predictions.index == sample_id
        ]
        if match.empty:
            raise IDSAgentError(f"Validation sample {sample_id} was not found.")
        return self._cohort_for_row(match.iloc[0], sample_id)

    def _cohort_for_row(self, row: pd.Series, sample_id: int) -> dict[str, Any]:
        probabilities = {
            label.removeprefix("__prob_").removesuffix("__"): float(row[label])
            for label in row.index if label.startswith("__prob_")
        }
        return _json_safe({
            "sample_id": int(sample_id), "true_label": str(row["__true_label__"]),
            "predicted_label": str(row["__predicted_label__"]),
            "confidence": float(row["__confidence__"]), "correct": bool(row["__correct__"]),
            "probabilities": probabilities,
            "feature_values": row[self.state.feature_columns].to_dict(),
            "evidence": self._evidence(row[self.state.feature_columns], float(row["__confidence__"])),
            "explanation_method": "largest-magnitude observed values; not causal attribution",
        })

    def attack_summary(self) -> dict[str, Any]:
        if self.state is None:
            raise IDSAgentError("Train the IDS model before requesting attack analysis.")
        report = self.state.metrics.get("classification_report", {})
        classes = [item for item in self.state.classes if not self._is_benign(item)]
        per_class = {item: report.get(item, {}) for item in classes}
        hardest = min(classes, key=lambda item: per_class[item].get("recall", 1.0)) if classes else None
        return _json_safe({"classes": self.state.classes, "attack_classes": classes,
                           "per_class": per_class, "hardest_attack": hardest,
                           "class_counts": self.state.profile.get("class_counts", {})})

    def feature_analysis(self) -> dict[str, Any]:
        if self.state is None:
            raise IDSAgentError("Train the IDS model before requesting feature analysis.")
        model = self.state.model
        if hasattr(model, "feature_importances_"):
            values = model.feature_importances_
            method = "model-native feature importance"
        elif hasattr(model, "named_steps") and hasattr(model.named_steps.get("model"), "feature_importances_"):
            values = model.named_steps["model"].feature_importances_
            method = "model-native feature importance"
        else:
            values = np.zeros(len(self.state.feature_columns))
            method = "No direct attribution available for this model"
        ranked = sorted(zip(self.state.feature_columns, values), key=lambda item: item[1], reverse=True)
        return {"method": method, "warning": "Importance is associative, not causal.",
                "features": [{"feature": name, "importance": float(value)} for name, value in ranked[:20]]}

    @staticmethod
    def _make_model(model_name: str) -> Any:
        if model_name == "logistic_regression":
            return Pipeline([
                ("imputer", SimpleImputer(strategy="median")),
                ("scale", StandardScaler()),
                ("model", LogisticRegression(max_iter=500, class_weight="balanced")),
            ])
        if model_name == "random_forest":
            return Pipeline([
                ("imputer", SimpleImputer(strategy="median")),
                ("model", RandomForestClassifier(
                    n_estimators=200, random_state=42, n_jobs=-1, class_weight="balanced_subsample"
                )),
            ])
        if model_name == "tabpfn":
            try:
                from dotenv import load_dotenv
                from tabpfn_client import TabPFNClassifier
            except ImportError as error:
                raise IDSAgentError(
                    "TabPFN client is not installed. Install requirements.txt before using the primary model."
                ) from error
            load_dotenv(Path(".env"))
            if not os.getenv("TABPFN_TOKEN"):
                raise IDSAgentError(
                    "TABPFN_TOKEN is missing. The local native TabPFN artifact is not used as a silent fallback; "
                    "configure the authenticated TabPFN client or explicitly run a baseline."
                )
            return TabPFNClassifier.create_default_for_version(
                "v3.5",
                random_state=42,
                fit_mode="fit_preprocessors",
            )
        raise IDSAgentError("model_name must be tabpfn, random_forest, or logistic_regression.")

    def predict(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if self.state is None:
            raise IDSAgentError("Train a model before predicting.")
        if not records:
            raise IDSAgentError("At least one traffic record is required.")
        inputs = pd.DataFrame(records).reindex(columns=self.state.feature_columns)
        inputs = inputs.apply(pd.to_numeric, errors="coerce")
        probabilities = self.state.model.predict_proba(inputs)
        predictions = self.state.model.classes_[np.argmax(probabilities, axis=1)]
        baseline_predictions = {}
        if self.state.baseline_models:
            for name, model in self.state.baseline_models.items():
                baseline_predictions[name] = model.predict(inputs)
        results = []
        for index, (prediction, row) in enumerate(zip(predictions, probabilities)):
            confidence = float(np.max(row))
            positive_probabilities = row[row > 0]
            entropy = float(
                -np.sum(positive_probabilities * np.log(positive_probabilities)) / np.log(len(row))
            )
            results.append({
                "record_index": index,
                "prediction": str(prediction),
                "is_attack": not self._is_benign(prediction),
                "confidence": confidence,
                "uncertainty": entropy,
                "model_agreement": {
                    name: str(values[index]) for name, values in baseline_predictions.items()
                },
                "models_agree": all(str(values[index]) == str(prediction)
                                    for values in baseline_predictions.values()),
                "should_investigate": bool(confidence < 0.9 or not all(
                    str(values[index]) == str(prediction) for values in baseline_predictions.values()
                )),
                "probabilities": {str(label): float(value) for label, value in zip(self.state.model.classes_, row)},
                "evidence": self._evidence(inputs.iloc[index], confidence),
            })
        return _json_safe(results)

    def validation_examples(self) -> dict[str, Any]:
        """Return one held-out benign row and one held-out attack row.

        These rows were excluded from model fitting and retain their observed
        validation labels so the UI can test real dataset examples rather
        than fabricated feature values.
        """
        if self.state is None:
            raise IDSAgentError("Train the IDS model before requesting validation examples.")
        rows = self.state.validation_rows
        labels = rows["__label__"].astype(str)
        benign = rows[labels.map(self._is_benign)]
        attack = rows[~labels.map(self._is_benign)]
        if benign.empty or attack.empty:
            raise IDSAgentError("The held-out validation split must contain benign and attack rows.")

        def serialize(row: pd.Series, expected_label: str) -> dict[str, Any]:
            record = {
                name: float(value) if pd.notna(value) else None
                for name, value in row[self.state.feature_columns].items()
            }
            return {
                "expected_label": expected_label,
                "record": record,
            }

        benign_row = benign.iloc[0]
        attack_row = attack.iloc[0]
        return _json_safe({
            "source": "held_out_validation_split",
            "note": "Rows were not used to fit the model; predictions are checked against their held-out labels.",
            "benign": serialize(benign_row, str(benign_row["__label__"])),
            "attack": serialize(attack_row, str(attack_row["__label__"])),
        })

    def mock_predict(self, kind: str, count: int = 5) -> dict[str, Any]:
        """Generate bounded synthetic records from the trained feature distribution."""
        if self.state is None:
            raise IDSAgentError("Train a model before running a mock prediction.")
        if kind not in {"attack", "benign"}:
            raise IDSAgentError("Mock kind must be attack or benign.")
        count = max(1, min(count, 25))
        labels = self.state.training_rows["__label__"].astype(str)
        selected = ~labels.map(self._is_benign) if kind == "attack" else labels.map(self._is_benign)
        source = self.state.training_rows.loc[selected, self.state.feature_columns]
        if source.empty:
            raise IDSAgentError(f"No {kind} examples are available in the trained dataset.")
        sampled = source.sample(count, replace=True, random_state=42)
        records = []
        for _, row in sampled.iterrows():
            values = pd.to_numeric(row, errors="coerce").fillna(0.0).to_dict()
            records.append({name: float(value) for name, value in values.items()})
        predictions = self.predict(records)
        return {
            "data_type": "synthetic_from_training_distribution",
            "expected_kind": kind,
            "rows": count,
            "attack_predictions": sum(item["is_attack"] for item in predictions),
            "benign_predictions": sum(not item["is_attack"] for item in predictions),
            "records": records,
            "predictions": predictions,
        }

    def _is_benign(self, label: Any) -> bool:
        value = str(label).strip().upper()
        if value == "BENIGN":
            return True
        return self.state is not None and self.state.label_column.lower() == "is_attack" and value == "0"

    def _evidence(self, row: pd.Series, confidence: float) -> list[str]:
        evidence = []
        missing = int(row.isna().sum())
        if missing:
            evidence.append(f"{missing} feature values were missing and median-imputed.")
        numeric = pd.to_numeric(row, errors="coerce").dropna()
        if len(numeric):
            largest = numeric.abs().sort_values(ascending=False).index[0]
            evidence.append(f"Highest-magnitude observed feature: {largest}.")
        evidence.append("High confidence" if confidence >= 0.8 else "Review manually: model confidence is below 0.8.")
        return evidence

    def investigate(self, question: str) -> dict[str, Any]:
        if self.state is None:
            raise IDSAgentError("Train a model before investigating.")
        text = question.lower()
        if "compare" in text or "better than" in text or "random forest" in text:
            comparison = self.compare_baselines()["comparison"]
            primary = comparison[self.state.model_name]
            baseline = comparison.get("random_forest", {})
            metric = "macro_f1"
            outcome = "better" if primary.get(metric, 0) > baseline.get(metric, 0) else "worse or equal"
            return {"answer": f"TabPFN is {outcome} than Random Forest on macro-F1 in this experiment.",
                    "metric": metric, "tabpfn": primary, "random_forest": baseline}
        if "reliab" in text or "calibrat" in text or "confidence" in text or "confident" in text:
            return {"answer": "Probabilities are uncalibrated model outputs; reliability is measured with ECE and Brier score.",
                    "reliability": self.reliability_report()}
        if "uncertain" in text or "review" in text or "least reliable" in text:
            return {"answer": "These are the lowest-confidence held-out predictions for analyst review.",
                    "predictions": self.uncertain_predictions()}
        if "highest-risk" in text or "high risk" in text or "investigate next" in text:
            return {"answer": "These alerts are ranked using TabPFN confidence, observed validation errors, and model disagreement.",
                    "alerts": self.high_risk_alerts()}
        if "agree" in text or "disagreement" in text:
            return {"answer": "These validation samples have different model predictions.",
                    "predictions": self.model_disagreement()}
        if "false positive" in text:
            return {"answer": "Benign validation samples incorrectly flagged as attacks.",
                    "predictions": self.false_positives()}
        if "false negative" in text or "missed attack" in text:
            return {"answer": "Attack validation samples missed by the model.",
                    "predictions": self.false_negatives()}
        if "high confidence" in text and "mistake" in text:
            return {"answer": "Incorrect held-out predictions ranked by confidence.",
                    "predictions": self.high_confidence_errors()}
        if "which attacks" in text or "hardest" in text or "attack class" in text:
            return {"answer": "Per-class attack performance from the held-out validation split.",
                    "attack_summary": self.attack_summary()}
        if any(word in text for word in ("metric", "accuracy", "f1", "auc", "performance")):
            return {"answer": "Model evaluation metrics from the held-out validation split.", "metrics": self.state.metrics}
        if any(word in text for word in ("feature", "column", "input")):
            return {"answer": "Numeric traffic features used by the trained model.", "features": self.state.feature_columns}
        if any(word in text for word in ("class", "attack", "label")):
            return {
                "answer": "The model predicts the dataset label. Any non-BENIGN class is treated as an attack.",
                "label_column": self.state.label_column,
                "classes": self.state.classes,
                "class_counts": self.state.profile.get("class_counts", {}),
            }
        return {
            "answer": "I can explain metrics, features, labels/classes, or score supplied traffic records.",
            "available_questions": ["What are the model metrics?", "Which features were used?", "What attacks were found?"],
        }

    def status(self) -> dict[str, Any]:
        if self.state is None:
            return {"stage": "dataset_not_loaded", "trained": False}
        details = self._model_details(self.state.model_name, self.state.model)
        return {"stage": "investigation_ready", "trained": True,
                "primary_model": (
                    "TabPFN v3.5 (requested)"
                    if self.state.model_name == "tabpfn"
                    else self.state.model_name
                ),
                "model": self.state.model_name, "label_column": self.state.label_column,
                "model_details": details,
                "classes": self.state.classes, "metrics": self.state.metrics,
                "reliability_available": bool(self.state.reliability)}
