#!/usr/bin/env python3
"""
STEP 4 — TEMPORAL NETWORK WORLD MODEL (LSTM ARCHITECTURE)

Multi-head LSTM Neural Network for Direct Multi-Horizon Network Attack Forecasting.
Inputs: Sequence of temporal network state windows (batch_size, seq_len=30, feature_dim=27)

Outputs:
1. curr_prob / curr_logits: Attack probability at step t (Scalar [0, 1])
2. forecast_prob / forecast_logits: Future attack probability vector for steps t+1 ... t+5 (Vector [5])
3. stage_logits: MITRE attack stage classification (Multi-class logits [num_stages])
"""

import os
import json
import logging
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Dict, Any, Tuple, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class LSTMWorldModel(nn.Module):
    """
    Temporal LSTM World Model for Network Security Attack Forecasting.
    Uses multi-head output for direct multi-horizon temporal forecasting:
    concurrent current state classification (t), multi-step future forecasting (t+1 ... t+K),
    and MITRE ATT&CK stage classification.
    """
    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 64,
        num_layers: int = 2,
        dropout: float = 0.2,
        horizon_steps: int = 5,
        num_stages: int = 6
    ):
        super(LSTMWorldModel, self).__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.horizon_steps = horizon_steps
        self.num_stages = num_stages

        # Temporal Sequence Feature Extractor
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0
        )

        # Shared Dense Representation Layer
        self.fc_shared = nn.Linear(hidden_dim, 32)
        self.dropout_shared = nn.Dropout(dropout)

        # Output Head 1: Current Attack Probability Logits
        self.head_current = nn.Linear(32, 1)

        # Output Head 2: Future Attack Forecast Timeline Logits (Horizon K=5)
        self.head_forecast = nn.Linear(32, horizon_steps)

        # Output Head 3: MITRE ATT&CK Stage Classification Logits
        self.head_stage = nn.Linear(32, num_stages)

    def forward(self, x: torch.Tensor, return_logits: bool = False) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        Input x: (batch_size, seq_len, input_dim)
        Returns:
            If return_logits is True:
                curr_logits: (batch_size, 1)
                forecast_logits: (batch_size, horizon_steps)
                stage_logits: (batch_size, num_stages)
            If return_logits is False:
                curr_prob: (batch_size, 1)
                forecast_prob: (batch_size, horizon_steps)
                stage_logits: (batch_size, num_stages)
        """
        lstm_out, (hn, cn) = self.lstm(x)
        last_hidden = lstm_out[:, -1, :]  # (batch_size, hidden_dim)

        shared_rep = F.relu(self.fc_shared(last_hidden))
        shared_rep = self.dropout_shared(shared_rep)

        curr_logits = self.head_current(shared_rep)
        forecast_logits = self.head_forecast(shared_rep)
        stage_logits = self.head_stage(shared_rep)

        if return_logits:
            return curr_logits, forecast_logits, stage_logits

        curr_prob = torch.sigmoid(curr_logits)
        forecast_prob = torch.sigmoid(forecast_logits)
        return curr_prob, forecast_prob, stage_logits

    def predict_numpy(self, x_np: np.ndarray) -> Dict[str, Any]:
        """Runs numpy array inference and returns python dictionary predictions."""
        self.eval()
        with torch.no_grad():
            if len(x_np.shape) == 2:
                x_np = np.expand_dims(x_np, axis=0)

            x_tensor = torch.tensor(x_np, dtype=torch.float32)
            curr_prob, forecast_prob, stage_logits = self.forward(x_tensor, return_logits=False)

            curr_p = curr_prob.squeeze().cpu().numpy().tolist()
            if isinstance(curr_p, float):
                curr_p = [curr_p]

            fore_p = forecast_prob.cpu().numpy().tolist()
            if len(fore_p) == 1:
                fore_p = fore_p[0]

            stage_probs = F.softmax(stage_logits, dim=-1).cpu().numpy()
            pred_stages = np.argmax(stage_probs, axis=-1).tolist()

            return {
                "current_probability": float(curr_p[0]),
                "forecast_timeline": [float(p) for p in (fore_p if isinstance(fore_p, list) else [fore_p])],
                "predicted_stage_idx": int(pred_stages[0] if isinstance(pred_stages, list) else pred_stages),
                "stage_probabilities": [float(p) for p in stage_probs[0]]
            }


if __name__ == "__main__":
    model = LSTMWorldModel(input_dim=27)
    dummy_input = torch.randn(8, 30, 27)
    c, f, s = model(dummy_input)
    print("LSTM World Model initialized successfully.")
    print("Current output shape:", c.shape)
    print("Forecast output shape:", f.shape)
    print("Stage output shape:", s.shape)
