try:
    import pandas as pd
    print(f"pandas OK: {pd.version}")
except Exception as e:
    print(f"pandas FAIL: {e}")

try:
    import numpy as np
    print(f"numpy OK: {np.version}")
except Exception as e:
    print(f"numpy FAIL: {e}")

try:
    import joblib
    print("joblib OK")
except Exception as e:
    print(f"joblib FAIL: {e}")

try:
    from scipy.sparse import hstack
    print("scipy OK")
except Exception as e:
    print(f"scipy FAIL: {e}")

try:
    import tldextract
    print("tldextract OK")
except Exception as e:
    print(f"tldextract FAIL: {e}")

print("DONE")