import numpy as np
from ebpfguard import simulator
from ebpfguard.autoencoder import Autoencoder
from ebpfguard.detector import detect
from ebpfguard.features import N_FEATURES, windowize


def _trained():
    X = np.array(windowize(simulator.stream(200, seed=1))["web-1"])
    return Autoencoder(N_FEATURES).fit(X)


def test_feature_shape():
    X = windowize(simulator.stream(5))["web-1"]
    assert len(X) == 5 and all(len(x) == N_FEATURES for x in X)


def test_detects_every_attack_type():
    m = _trained()
    for atk in simulator.ATTACKS:
        alerts = list(detect(simulator.stream(20, seed=7, attack_every=5, attack=atk), m))
        flagged = [i for i, a in enumerate(alerts) if a.suspicious]
        assert {4, 9, 14, 19} <= set(flagged), (atk, flagged)


def test_low_false_positive_rate():
    m = _trained()
    alerts = list(detect(simulator.stream(300, seed=42), m))
    assert sum(a.suspicious for a in alerts) / len(alerts) < 0.05


def test_save_load_roundtrip(tmp_path):
    m = _trained(); m.save(str(tmp_path / "m.pt"))
    m2 = Autoencoder.load(str(tmp_path / "m.pt"))
    x = np.array(windowize(simulator.stream(3))["web-1"])
    assert np.allclose(m.score(x), m2.score(x))
