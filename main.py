"""Command-line entry point for the MCP-powered IDS agent."""

from __future__ import annotations

import argparse
import json

from src.ids_agent import IDSInvestigator


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile and train the local IDS investigator.")
    parser.add_argument("dataset", help="Path to a CSV or Parquet dataset")
    parser.add_argument("--label-column", default=None)
    parser.add_argument(
        "--model",
        default="tabpfn",
        choices=("tabpfn", "random_forest", "logistic_regression"),
    )
    parser.add_argument("--max-rows", type=int, default=100_000)
    args = parser.parse_args()

    investigator = IDSInvestigator()
    profile = investigator.load_dataset(args.dataset, max_rows=args.max_rows)
    result = investigator.train(args.label_column, args.model, args.max_rows)
    print(json.dumps({"profile": profile, "training": result}, indent=2, default=str))


if __name__ == "__main__":
    main()