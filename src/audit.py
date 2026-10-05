import glob, os
import numpy as np
import pandas as pd

rows = []
for path in sorted(glob.glob("data/**/*.csv", recursive=True)):
    df = pd.read_csv(path, encoding="latin1", low_memory=False)
    df.columns = df.columns.str.strip()
    num = df.select_dtypes(include=[np.number])
    labels = df["Label"].value_counts().to_dict() if "Label" in df else {}
    rows.append({
        "file": os.path.basename(path),
        "rows": len(df),
        "cols": df.shape[1],
        "inf_cells": int(np.isinf(num).sum().sum()),
        "nan_cells": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "labels": labels,
    })
    print(rows[-1])
    del df, num

os.makedirs("results", exist_ok=True)
pd.DataFrame(rows).to_csv("results/data_audit.csv", index=False)