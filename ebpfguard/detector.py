"""Streaming detector: windows events per container, scores, raises alerts."""
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, List, Optional

import numpy as np

from .autoencoder import Autoencoder
from .features import FEATURE_NAMES, window_features
from . import events as E


@dataclass
class Alert:
    window_start: float
    container: str
    score: float
    threshold: float
    suspicious: bool
    reasons: List[tuple]
    features: np.ndarray

    def __str__(self):
        tag = "ALERT" if self.suspicious else "ok   "
        s = f"[{tag}] t={self.window_start:7.1f}s {self.container:<10} score={self.score:8.3f} (thr {self.threshold:.3f})"
        if self.suspicious:
            s += "  top: " + ", ".join(f"{n}" for n, _ in self.reasons)
        return s


def detect(events: Iterable[E.Event], model: Autoencoder, window: float = 5.0,
           skip_first: bool = False) -> Iterator[Alert]:
    """Consume an event stream (ordered by time); emit one Alert per container-window."""
    cur = {}                      # container -> (window index, [events])
    seen = set()                  # containers whose (possibly partial) first window was skipped
    def flush(c, idx, evs):
        x = window_features(evs, window)
        s = float(model.score(x)[0])
        sus = s > model.threshold
        return Alert(idx * window, c, s, model.threshold, sus,
                     model.explain(x, FEATURE_NAMES) if sus else [], x)
    for e in events:
        idx = int(e.ts // window)
        if e.container in cur and cur[e.container][0] != idx:
            if skip_first and e.container not in seen:
                seen.add(e.container)         # live capture began mid-window
            else:
                yield flush(e.container, *cur[e.container])
            del cur[e.container]
        cur.setdefault(e.container, (idx, []))[1].append(e)
    for c, (idx, evs) in cur.items():
        if skip_first and c not in seen:
            continue
        yield flush(c, idx, evs)
