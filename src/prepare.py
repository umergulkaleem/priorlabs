import glob, os
import numpy as np
import pandas as pd

os.makedirs("data/processed", exist_ok=True)
os.makedirs("results", exist_ok=True)

frames = []
for path in sorted(glob.glob("data/**/*.csv", recursive=True)):
    df = pd.read_csv(path, encoding="latin1", low_memory=False)
    df.columns = df.columns.str.strip()
    df["Label"] = (df["Label"].astype(str)
                   .str.replace(r"[^\x20-\x7E]+", "-", regex=True).str.strip())
    feats = [c for c in df.columns if c != "Label"]
    df[feats] = df[feats].apply(pd.to_numeric, errors="coerce").astype("float32")
    df[feats] = df[feats].replace([np.inf, -np.inf], np.nan)
    base = os.path.basename(path)
    df["day"] = base.split("-")[0].capitalize()
    df["file"] = base
    frames.append(df)

data = pd.concat(frames, ignore_index=True)
n0 = len(data)
feats = [c for c in data.columns if c not in ("Label", "day", "file")]

data = data.drop_duplicates(subset=feats + ["Label"]).reset_index(drop=True)
n1 = len(data)
conflicts = int(data.duplicated(subset=feats, keep=False).sum())

data["is_attack"] = (data["Label"] != "BENIGN").astype("int8")
data["day"] = pd.Categorical(
    data["day"], ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"], ordered=True)

data.to_parquet("data/processed/cicids2017_clean.parquet", index=False)
summary = data.groupby(["day", "Label"], observed=True).size().rename("rows")
summary.to_csv("results/clean_counts.csv")

print(summary.to_string())
print("rows before dedup:", n0, "| after:", n1, "| removed:", n0 - n1)
print("rows with identical features but different labels:", conflicts)
print("feature columns:", len(feats))