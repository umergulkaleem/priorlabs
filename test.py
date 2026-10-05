"""Small local TabPFN smoke test.

This uses the bundled native model artifact and does not call the TabPFN API.
Run it once only when checking the local model installation.
"""

import time

import numpy as np
from tabpfn import TabPFNClassifier

rng = np.random.default_rng(0)
X = rng.normal(size=(200, 70))
y = (X[:, 0] + X[:, 1] > 0).astype(int)
Xt = rng.normal(size=(25, 70))
clf = TabPFNClassifier(model_path="models/tabpfn-v3.5-20260909.safetensors")
t = time.time()
clf.fit(X, y)
fit_seconds = time.time() - t
t = time.time()
probabilities = clf.predict_proba(Xt)
predict_seconds = time.time() - t
print(
    f"local smoke test: train_rows=200 predict_rows={len(Xt)} "
    f"fit={fit_seconds:.1f}s predict={predict_seconds:.1f}s "
    f"shape={probabilities.shape}",
    flush=True,
)