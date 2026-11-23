"""Command line: train on normal behaviour, then detect on a live/simulated stream."""
import argparse
import sys

import numpy as np

from . import simulator
from .autoencoder import Autoencoder
from .detector import detect
from .features import FEATURE_NAMES, N_FEATURES, windowize


def _source(args, **kw):
    if args.source == "ebpf":
        from .collector_ebpf import collect
        return collect(args.window, getattr(args, "container", None))
    return simulator.stream(args.windows, args.window, **kw)


def cmd_train(a):
    evs = list(simulator.stream(a.windows, a.window, seed=a.seed)) if a.source == "sim" else None
    if evs is None:   # live: gather `windows` windows of (assumed normal) traffic
        import itertools, time
        end = time.time() + a.windows * a.window
        evs = list(itertools.takewhile(lambda e: e.ts < end, _source(a)))
    # live capture starts/ends mid-window: drop the partial first and last windows
    per = windowize(evs, a.window)
    if a.source == "ebpf":
        per = {c: vs[1:-1] for c, vs in per.items()}
    X = np.array([v for vs in per.values() for v in vs])
    m = Autoencoder(N_FEATURES).fit(X)
    m.window = a.window
    m.save(a.model)
    print(f"trained on {len(X)} windows -> {a.model}  (alert threshold {m.threshold:.3f})")


def cmd_detect(a):
    m = Autoencoder.load(a.model)
    if m.window and m.window != a.window:
        print(f"note: model was trained with {m.window}s windows; using that instead of {a.window}s")
        a.window = m.window
    kw = {"seed": a.seed + 100}
    if a.source == "sim":
        kw.update(attack_every=a.attack_every)
    n_alert = 0
    for al in detect(_source(a, **kw), m, a.window, skip_first=(a.source == 'ebpf')):
        if al.suspicious or a.verbose:
            print(al)
        n_alert += al.suspicious
    print(f"done: {n_alert} alert(s)")


def cmd_demo(a):
    a.model = "model.pt"; a.source = "sim"
    cmd_train(a)
    a.attack_every, a.verbose = 5, True
    cmd_detect(a)


def main(argv=None):
    p = argparse.ArgumentParser(prog="ebpfguard", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("train", cmd_train), ("detect", cmd_detect), ("demo", cmd_demo)):
        s = sub.add_parser(name)
        s.add_argument("--source", choices=["sim", "ebpf"], default="sim",
                       help="sim = synthetic telemetry; ebpf = live Docker (needs root + bcc)")
        s.add_argument("--model", default="model.pt")
        s.add_argument("--windows", type=int, default=200 if name != "detect" else 40)
        s.add_argument("--window", type=float, default=5.0, help="window length in seconds")
        s.add_argument("--container", help="(ebpf) only monitor containers whose name contains this")
        s.add_argument("--seed", type=int, default=1)
        s.add_argument("--attack-every", type=int, default=5)
        s.add_argument("-v", "--verbose", action="store_true", help="also print normal windows")
        s.set_defaults(fn=fn)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
