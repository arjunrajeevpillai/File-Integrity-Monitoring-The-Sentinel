# File-Integrity-Monitoring-The-Sentinel
Build a Python-based File Integrity Monitor that detects unauthorized file changes using SHA-256 hashing.
**Objective:** Build a Python-based File Integrity Monitor that detects unauthorized file changes using SHA-256 hashing.

**How it works:**
1. **Baseline** — On startup, capture SHA-256 hashes of all files in monitored directory
2. **Polling** — Every 2 seconds, re-scan and compare against baseline
3. **Alerting** — Trigger flags for New / Modified / Deleted files

**The Sentinel — Core Script:**

```python
import hashlib
import os
import time

MONITOR_DIR = "/vault"
POLL_INTERVAL = 2

def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def build_baseline(directory):
    baseline = {}
    for fname in os.listdir(directory):
        fpath = os.path.join(directory, fname)
        if os.path.isfile(fpath):
            baseline[fpath] = hash_file(fpath)
    return baseline

def monitor(directory):
    print(f"[SENTINEL ACTIVE] Monitoring {directory}")
    baseline = build_baseline(directory)

    while True:
        time.sleep(POLL_INTERVAL)
        current = build_baseline(directory)

        # Detect new files
        for fpath in current:
            if fpath not in baseline:
                print(f"[NEW FILE] {fpath}")

        # Detect modified or deleted files
        for fpath in baseline:
            if fpath not in current:
                print(f"[DELETED] {fpath}")
            elif current[fpath] != baseline[fpath]:
                print(f"[MODIFIED] {fpath}")

        baseline = current

if __name__ == "__main__":
    monitor(MONITOR_DIR)
```

**Test commands used:**

```bash
# Check hash manually
sha256sum vault/test.txt

# Run Sentinel
python3 sentinel.py

# Simulate file modification (attack)
echo "malware code" >> vault/test.txt

# Simulate new file creation
touch vault/hacker.txt
```

**Detections confirmed:**
- `NEW FILE: /vault/hacker.txt` — detected within 2 seconds
- `MODIFIED: /vault/test.txt` — SHA-256 mismatch triggered alert
- `MODIFIED: /vault/hacker.txt` — subsequent injection detected

**Tools:** Python 3, SHA-256, Kali Linux, Bash
