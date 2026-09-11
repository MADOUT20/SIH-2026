#!/usr/bin/env python3
"""
STEP 8 & STEP 9 — FUTURE FORECASTING & EXPLAINABILITY ENGINE

Inference engine for temporal network attack forecasting:
1. Loads trained PyTorch LSTM World Model and StandardScaler artifacts.
2. Accepts sequence of network state windows (WINDOW_SIZE=30, num_features=27).
3. Computes current attack probability, K-step future probability timeline (horizon=5),
   and predicted MITRE attack stage.
4. Computes gradient-based feature attribution for explainability (saliency / attribution).
"""

import os
import sys
import json
import joblib
import logging
import numpy as np
import torch
import torch.nn.functional as F
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from models.network_world_model import LSTMWorldModel
from scripts.window_generator import WINDOW_SIZE, PREDICTION_HORIZON

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TRAINED_DIR = os.path.join(BASE_DIR, "models", "trained")

STAGE_NAME_LOOKUP = {
    0: "Normal / Benign",
    1: "Credential Access (Brute Force)",
    2: "Initial Access (Exploitation)",
    3: "Privilege Escalation / Execution",
    4: "Command and Control (Bot)",
    5: "Impact (Denial of Service)"
}


class ForecastEngine:
    def __init__(self, trained_dir: str = TRAINED_DIR):
        self.trained_dir = trained_dir
        self.pth_path = os.path.join(trained_dir, "world_model.pth")
        self.scaler_path = os.path.join(trained_dir, "scaler.pkl")
        self.config_path = os.path.join(trained_dir, "feature_config.json")

        self.model: Optional[LSTMWorldModel] = None
        self.scaler = None
        self.feature_names: List[str] = []
        self.num_features = 27
        self.horizon_steps = 5

        self.load_artifacts()

    def load_artifacts(self):
        """Loads trained PyTorch model, scaler, and feature configuration."""
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                config = json.load(f)
                self.feature_names = config.get("feature_names", [])
                self.num_features = config.get("num_features", len(self.feature_names))
                self.horizon_steps = config.get("prediction_horizon", 5)

        if os.path.exists(self.scaler_path):
            self.scaler = joblib.load(self.scaler_path)
            logging.info("Loaded StandardScaler successfully.")

        if os.path.exists(self.pth_path):
            checkpoint = torch.load(self.pth_path, map_location=torch.device("cpu"))
            self.model = LSTMWorldModel(
                input_dim=checkpoint.get("input_dim", self.num_features),
                hidden_dim=checkpoint.get("hidden_dim", 64),
                num_layers=checkpoint.get("num_layers", 2),
                horizon_steps=checkpoint.get("horizon_steps", self.horizon_steps),
                num_stages=checkpoint.get("num_stages", 6)
            )
            self.model.load_state_dict(checkpoint["model_state_dict"])
            self.model.eval()
            logging.info(f"Loaded LSTM World Model from: {self.pth_path}")
        else:
            logging.warning(f"No trained model found at {self.pth_path}. Run scripts/train_world_model.py first.")

    def compute_feature_attribution(self, x_tensor: torch.Tensor) -> List[Dict[str, Any]]:
        """
        Gradient-based Feature Attribution (Integrated Gradient / Saliency Attribution) for LSTM.
        Computes per-feature importance, directional impact (+/-), raw state value, and domain description.
        """
        x_clone = x_tensor.clone().detach().requires_grad_(True)
        self.model.zero_grad()

        curr_prob, forecast_prob, _ = self.model(x_clone)
        target_score = curr_prob.sum() + forecast_prob.sum()
        target_score.backward()

        # Gradients wrt input sequence X: (1, window_size, num_features)
        raw_grads = x_clone.grad.data.cpu().numpy()[0]   # (30, num_features)
        abs_grads = np.abs(raw_grads)
        x_val = x_tensor.detach().cpu().numpy()[0]        # (30, num_features)

        # Attribution per feature channel = mean(|grad * X|) across time window
        attributions = np.mean(abs_grads * np.abs(x_val), axis=0)  # (num_features,)
        directional_grads = np.mean(raw_grads, axis=0)             # (num_features,)

        total_attr = np.sum(attributions) + 1e-8
        norm_attributions = attributions / total_attr

        top_indices = np.argsort(norm_attributions)[::-1][:6]
        top_features = []

        for idx in top_indices:
            fname = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
            score = float(norm_attributions[idx])
            raw_v = float(x_val[-1, idx]) if len(x_val) > 0 else 0.0
            dir_v = "+" if directional_grads[idx] >= 0 else "-"

            # Domain category description generator
            if "flag" in fname or fname in ["syn_flag_cnt", "ack_flag_cnt", "rst_flag_cnt", "fin_flag_cnt", "psh_flag_cnt"]:
                desc = f"TCP Control Flag ({fname}): raw count {raw_v:.0f}"
            elif "port" in fname or fname == "is_high_risk_port":
                desc = f"Port Analysis ({fname}): active risk flag {raw_v:.0f}"
            elif "byts" in fname or "pkts" in fname or "len" in fname or "ratio" in fname:
                desc = f"Flow Traffic Statistic ({fname}): current value {raw_v:.2f}"
            elif "iat" in fname or "duration" in fname:
                desc = f"Inter-Arrival / Duration Timing ({fname}): current value {raw_v:.4f}s"
            else:
                desc = f"Network Feature ({fname}): current value {raw_v:.2f}"

            top_features.append({
                "feature": fname,
                "importance": round(score, 4),
                "direction": dir_v,
                "raw_value": round(raw_v, 4),
                "description": desc
            })

        return top_features


    def forecast(self, input_sequence: np.ndarray) -> Dict[str, Any]:
        """
        Accepts raw or scaled input sequence X of shape (window_size=30, num_features)
        or (1, 30, num_features). Returns formatted forecast JSON using trained PyTorch model.
        """
        if self.model is None:
            self.load_artifacts()

        if self.model is None:
            return {
                "error": "Model not trained/available",
                "status": "model_unavailable",
                "message": "Trained model checkpoint (world_model.pth) was not found."
            }

        # Shape formatting
        if len(input_sequence.shape) == 2:
            input_sequence = np.expand_dims(input_sequence, axis=0)

        # Scale features if scaler is available and input is unscaled
        seq_scaled = input_sequence.copy()
        if self.scaler is not None and np.max(np.abs(input_sequence)) > 50:
            b, w, f = seq_scaled.shape
            seq_reshaped = seq_scaled.reshape(-1, f)
            seq_scaled = self.scaler.transform(seq_reshaped).reshape(b, w, f)

        x_tensor = torch.tensor(seq_scaled, dtype=torch.float32)

        self.model.eval()
        with torch.no_grad():
            curr_prob_t, forecast_prob_t, stage_logits_t = self.model(x_tensor)
            curr_p = float(curr_prob_t.squeeze().cpu().numpy())
            fore_p = forecast_prob_t.cpu().numpy()[0].tolist()

            stage_probs = F.softmax(stage_logits_t, dim=-1).cpu().numpy()[0]
            pred_stage_idx = int(np.argmax(stage_probs))

        # Gradient-based feature attribution
        top_features = self.compute_feature_attribution(x_tensor)

        # Construct step-by-step forecast array
        forecast_list = []
        for step_i, prob in enumerate(fore_p, start=1):
            forecast_list.append({
                "step": step_i,
                "probability": round(float(prob), 4)
            })

        predicted_stage_name = STAGE_NAME_LOOKUP.get(pred_stage_idx, "Unknown Threat")

        return {
            "current_probability": round(curr_p, 4),
            "forecast": forecast_list,
            "predicted_stage": predicted_stage_name,
            "predicted_stage_index": pred_stage_idx,
            "stage_confidence": round(float(stage_probs[pred_stage_idx]), 4),
            "top_features": top_features,
            "window_size": input_sequence.shape[1],
            "prediction_horizon": len(forecast_list)
        }


# Global Singleton Instance for backend loading
forecast_engine = ForecastEngine()


if __name__ == "__main__":
    dummy_seq = np.random.randn(30, 27)
    res = forecast_engine.forecast(dummy_seq)
    print(json.dumps(res, indent=2))
