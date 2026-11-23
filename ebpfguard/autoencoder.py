"""Autoencoder anomaly detector (PyTorch)
"""
import numpy as np
import torch
from torch import nn


class Autoencoder:
    def __init__(self, n_features):
        # Encoder squeezes 12 features down to 3 numbers (the bottleneck / latent space)
        self.encoder = nn.Sequential(
            nn.Linear(n_features, 8), nn.Tanh(),
            nn.Linear(8, 3),
        )
        # Decoder rebuilds the 12 features from those 3 numbers
        self.decoder = nn.Sequential(
            nn.Tanh(),
            nn.Linear(3, 8), nn.Tanh(),
            nn.Linear(8, n_features),
        )
        self.n = n_features
        self.mean = torch.zeros(n_features)
        self.std = torch.ones(n_features)
        self.threshold = float("inf")
        self.window = None                     # window length (s) used for training

    def reconstruct(self, data):
        return self.decoder(self.encoder(data))

    def _prepare(self, X):
        """log1p shrinks big counts, then standardise to mean 0 / std 1."""
        x = torch.log1p(torch.tensor(np.atleast_2d(X), dtype=torch.float32))
        return (x - self.mean) / self.std

    def fit(self, X, epochs=600, lr=0.01, percentile=99.0, margin=1.5, min_threshold=0.1):
        x = torch.log1p(torch.tensor(X, dtype=torch.float32))
        self.mean = x.mean(0)
        self.std = x.std(0, unbiased=False).clamp(min=0.3)   # min keeps constant features finite
        data = self._prepare(X)

        torch.manual_seed(0)
        params = list(self.encoder.parameters()) + list(self.decoder.parameters())
        optimizer = torch.optim.Adam(params, lr=lr)
        for _ in range(epochs):
            loss = nn.functional.mse_loss(self.reconstruct(data), data)   # how badly we copy the input
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        # Alert threshold: take the error that `percentile`% of normal windows stay under
        # (99th by default), multiply by `margin` for headroom, never go below `min_threshold`.
        normal_errors = self.score(X)
        self.threshold = max(margin * float(np.percentile(normal_errors, percentile)), min_threshold)
        return self

    @torch.no_grad()
    def score(self, X):
        """Reconstruction error per window (mean squared error)."""
        data = self._prepare(X)
        return ((self.reconstruct(data) - data) ** 2).mean(1).numpy()

    @torch.no_grad()
    def explain(self, x, names, top=3):
        """The features the network rebuilt worst = the reasons for an alert."""
        data = self._prepare(x)
        error = ((self.reconstruct(data) - data) ** 2)[0].numpy()
        return [(names[i], float(error[i])) for i in np.argsort(error)[::-1][:top]]

    def save(self, path):
        torch.save({"encoder": self.encoder.state_dict(), "decoder": self.decoder.state_dict(), "n": self.n, "mean": self.mean, "std": self.std,
                    "threshold": self.threshold, "window": self.window}, path)

    @classmethod
    def load(cls, path):
        d = torch.load(path, map_location="cpu", weights_only=True)
        model = cls(d["n"])
        model.encoder.load_state_dict(d["encoder"])
        model.decoder.load_state_dict(d["decoder"])
        model.mean, model.std = d["mean"], d["std"]
        model.threshold, model.window = d["threshold"], d["window"]
        return model
