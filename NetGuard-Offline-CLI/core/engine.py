#!/usr/bin/env python3
import os
import json
import joblib
import logging
import numpy as np
import torch
import torch.nn.functional as F
from typing import Dict, Any, List, Optional
from .model import LSTMWorldModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Relative to this file in core/
ASSETS_DIR = os.path.join(os.path.dirname(__file__), "..", "assets")

STAGE_NAME_LOOKUP = {
    0: "Normal / Benign",
    1: "Credential Access (Brute Force)",
    2: "Initial Access (Exploitation)",
    3: "Privilege Escalation / Execution",
    4: "Command and Control (Bot)",
    5: "Impact (Denial of Service)"
}

class ForecastEngine:
    def __init__(self, trained_dir: str = ASSETS_DIR):
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
            logging.warning(f"No trained model found at {self.pth_path}.")

    def compute_feature_attribution(self, x_tensor: torch.Tensor) -> List[Dict[str, Any]]:
        x_clone = x_tensor.clone().detach().requires_grad_(True)
        self.model.zero_grad()

        curr_prob, forecast_prob, _ = self.model(x_clone)
        target_score = curr_prob.sum() + forecast_prob.sum()
        target_score.backward()

        raw_grads = x_clone.grad.data.cpu().numpy()[0]
        abs_grads = np.abs(raw_grads)
        x_val = x_tensor.detach().cpu().numpy()[0]

        attributions = np.mean(abs_grads * np.abs(x_val), axis=0)
        directional_grads = np.mean(raw_grads, axis=0)

        total_attr = np.sum(attributions) + 1e-8
        norm_attributions = attributions / total_attr

        top_indices = np.argsort(norm_attributions)[::-1][:6]
        top_features = []

        for idx in top_indices:
            fname = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
            score = float(norm_attributions[idx])
            raw_v = float(x_val[-1, idx]) if len(x_val) > 0 else 0.0
            dir_v = "+" if directional_grads[idx] >= 0 else "-"

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
        if self.model is None:
            self.load_artifacts()

        if self.model is None:
            return {"error": "Model not trained/available", "status": "model_unavailable"}

        if len(input_sequence.shape) == 2:
            input_sequence = np.expand_dims(input_sequence, axis=0)

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

        top_features = self.compute_feature_attribution(x_tensor)

        forecast_list = []
        for step_i, prob in enumerate(fore_p, start=1):
            forecast_list.append({"step": step_i, "probability": round(float(prob), 4)})

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
