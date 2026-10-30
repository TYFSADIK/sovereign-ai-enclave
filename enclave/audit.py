"""Append-only, hash-chained audit log (same design as decision-black-box)."""
import hashlib
import json
import time


class Audit:
    def __init__(self, path=None):
        self.path, self.prev, self.events = path, "0" * 64, []

    def log(self, event, **kw):
        rec = {"t": time.time(), "event": event, **kw, "prev": self.prev}
        line = json.dumps(rec, sort_keys=True)
        self.prev = hashlib.sha256(line.encode()).hexdigest()
        self.events.append(rec)
        if self.path:
            with open(self.path, "a") as fh:
                fh.write(line + "\n")
