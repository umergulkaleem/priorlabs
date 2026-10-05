import os, sys, time
from dotenv import load_dotenv, find_dotenv

env_path = find_dotenv(usecwd=True)
load_dotenv(env_path, override=True)
print(".env found at:", env_path or "NOT FOUND", flush=True)
print("TABPFN_TOKEN set:", bool(os.environ.get("TABPFN_TOKEN")), flush=True)
if not os.environ.get("TABPFN_TOKEN"):
    sys.exit("Token missing. Check the variable name in .env and run from the project root.")
os.environ["TABPFN_NO_BROWSER"] = "1"   

import numpy as np
import tabpfn_client
from tabpfn_client import TabPFNClassifier

try:
    print("usage before:", tabpfn_client.get_api_usage(), flush=True)
except Exception as e:
    print("usage check failed:", repr(e), flush=True)

rng = np.random.default_rng(0)
X = rng.normal(size=(200, 70)); y = (X[:, 0] + X[:, 1] > 0).astype(int)
Xt = rng.normal(size=(25, 70))

clf = TabPFNClassifier()
t = time.time(); clf.fit(X, y); print(f"fit {time.time() - t:.1f}s", flush=True)
t = time.time(); p = clf.predict_proba(Xt); print(f"predict 25 rows {time.time() - t:.1f}s", flush=True)

try:
    print("usage after:", tabpfn_client.get_api_usage(), flush=True)
except Exception as e:
    print("usage check failed:", repr(e), flush=True)