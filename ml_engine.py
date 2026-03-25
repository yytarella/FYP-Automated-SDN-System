import joblib
import numpy as np
import pandas as pd
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class MLEngine:

    def __init__(self, model_dir="models"):
        try:
            self.model_cd = joblib.load(f"{model_dir}/tier1cd_xgb_model.pkl")
            bundle_a = joblib.load(f"{model_dir}/tier1a_behaviour_rf_model.pkl")
            bundle_b = joblib.load(f"{model_dir}/tier1b_academic_rf_model.pkl")

            self.model_a = bundle_a["model"]
            self.model_b = bundle_b["model"]
            self.feature_names = bundle_a["features"]          # Expected features for behaviour/academic
            self.label_encoder_a = bundle_a.get("label_encoder")
            self.label_encoder_b = bundle_b.get("label_encoder")
            self.feature_names_cd = self.model_cd.feature_names_in_

            self.behaviour_map = {
                0: "background",
                1: "academic",
                2: "chat",
                3: "bulk",
                4: "media"
            }

            self.executor = ThreadPoolExecutor(max_workers=3)
            logger.info(f"ML Engine initialized | AB features: {len(self.feature_names)}, CD features: {len(self.feature_names_cd)}")
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
            raise

    def safe_ratio(self, a, b):
        return 0 if b == 0 else a / b

    def infer(self, features_cd_dict, features_ab_dict, metadata):
        try:
            # Build CD vector in correct order
            X_cd = np.array([[features_cd_dict.get(name, 0) for name in self.feature_names_cd]])

            # Compute ratio features
            pl_ratio = self.safe_ratio(features_ab_dict.get("forward_pl_mean", 0),
                                       features_ab_dict.get("reverse_pl_mean", 0))
            iat_ratio = self.safe_ratio(features_ab_dict.get("forward_piat_mean", 0),
                                        features_ab_dict.get("reverse_piat_mean", 0))
            pps_ratio = self.safe_ratio(features_ab_dict.get("forward_pps_mean", 0),
                                        features_ab_dict.get("reverse_pps_mean", 0))

            features_ab_dict["pl_mean_ratio"] = pl_ratio
            features_ab_dict["iat_ratio"] = iat_ratio
            features_ab_dict["pps_ratio"] = pps_ratio

            # Build AB DataFrame with expected features
            X_ab = pd.DataFrame([[features_ab_dict.get(name, 0) for name in self.feature_names]],
                                columns=self.feature_names)

            # Parallel inference
            f_cd_proba = self.executor.submit(self.model_cd.predict_proba, X_cd)
            f_a = self.executor.submit(self.model_a.predict, X_ab)
            f_b = self.executor.submit(self.model_b.predict, X_ab)

            attack_probs = f_cd_proba.result()[0]
            attack_confidence = attack_probs[1] if len(attack_probs) > 1 else 0

            raw_behaviour = int(f_a.result()[0])
            raw_academic = int(f_b.result()[0])

            # Decode labels if encoders exist
            if self.label_encoder_a is not None:
                behaviour_label = self.label_encoder_a.inverse_transform([raw_behaviour])[0]
            else:
                behaviour_label = self.behaviour_map.get(raw_behaviour, "unknown")

            if self.label_encoder_b is not None:
                academic_label = self.label_encoder_b.inverse_transform([raw_academic])[0]
                academic = 1 if academic_label == "academic" else 0
            else:
                # Fallback: assume 0 = academic, 1 = non_academic (based on training)
                academic = 1 if raw_academic == 0 else 0

            packet_count = features_cd_dict.get("packet_count", 0)

            # Stricter attack detection
            final_attack = 0
            if attack_confidence > 0.95 and packet_count > 50:
                final_attack = 1

            logger.info(
                f"[ML] Result: attack={final_attack} (conf:{attack_confidence:.2f}), "
                f"behaviour={behaviour_label}, academic={academic}"
            )

            return {
                "attack": final_attack,
                "behaviour": behaviour_label,
                "academic": academic,
                "confidence": float(attack_confidence)
            }

        except Exception as e:
            logger.error(f"Inference pipeline failed: {e}", exc_info=True)
            return {
                "attack": 0,
                "behaviour": "unknown",
                "academic": 0,
                "confidence": 0.0
            }