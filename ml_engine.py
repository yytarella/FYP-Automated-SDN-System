import joblib
import numpy as np
import pandas as pd
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class MLEngine:

    def __init__(self, model_dir="models"):
        # Load models
        try:
            self.model_cd = joblib.load(f"{model_dir}/tier1cd_xgb_model.pkl")
            bundle_a = joblib.load(f"{model_dir}/tier1a_behaviour_rf_model.pkl")
            bundle_b = joblib.load(f"{model_dir}/tier1b_academic_rf_model.pkl")

            self.model_a = bundle_a["model"]
            self.model_b = bundle_b["model"]
            self.feature_names = bundle_a["features"]
            
            # Map numerical outputs to policy-friendly strings
            self.behaviour_map = {
                0: "background",
                1: "academic",
                2: "chat",
                3: "bulk",
                4: "media"
            }

            self.executor = ThreadPoolExecutor(max_workers=3)
            logger.info(f"ML Engine initialized | Feature count required: {len(self.feature_names)}")
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
            raise

    def safe_ratio(self, a, b):
        return 0 if b == 0 else a / b

    def add_ratio_features(self, features_ab):
        """
        Calculate flow ratios for model consistency.
        Indices: PL_mean(11/31), PIAT_mean(5/25), PPS_mean(17/37)
        """
        try:
            pl_ratio = self.safe_ratio(features_ab[11], features_ab[31])
            iat_ratio = self.safe_ratio(features_ab[5], features_ab[25])
            pps_ratio = self.safe_ratio(features_ab[17], features_ab[37])
            return features_ab + [pl_ratio, iat_ratio, pps_ratio]
        except IndexError:
            logger.warning("Feature vector AB is too short for ratio calculation")
            return features_ab

    def infer(self, features_cd, features_ab):
        try:
            X_cd = np.array(features_cd).reshape(1, -1)
            features_ab_full = self.add_ratio_features(features_ab)

            # Feature length validation
            if len(features_ab_full) != len(self.feature_names):
                logger.error(f"Dimension mismatch: {len(features_ab_full)} vs {len(self.feature_names)}")
                return {"attack": 0, "behaviour": "unknown", "academic": 0}

            X_ab = pd.DataFrame([features_ab_full], columns=self.feature_names)

            # Parallel inference
            f_cd_proba = self.executor.submit(self.model_cd.predict_proba, X_cd)
            f_a = self.executor.submit(self.model_a.predict, X_ab)
            f_b = self.executor.submit(self.model_b.predict, X_ab)

            # Attack detection with confidence threshold
            # index [0][1] is usually the probability of class 1 (Attack)
            attack_probs = f_cd_proba.result()[0]
            attack_confidence = attack_probs[1] if len(attack_probs) > 1 else 0
            
            # Behavior and Academic results
            raw_behaviour = int(f_a.result()[0])
            academic = int(f_b.result()[0])

            # Determine Attack status with stability filters
            # packet_count is usually at the end of the CD feature vector
            packet_count = features_cd[-2] if len(features_cd) > 2 else 0
            
            final_attack = 0
            if attack_confidence > 0.85: # High confidence threshold
                if packet_count > 15: # Ignore very first few packets to avoid false positives
                    final_attack = 1
                else:
                    logger.info(f"Suspicious flow detected but insufficient data. Packets: {packet_count}")

            behaviour_label = self.behaviour_map.get(raw_behaviour, "unknown")

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
            logger.error(f"Inference pipeline failed: {e}")
            return {
                "attack": 0, 
                "behaviour": "unknown", 
                "academic": 0
            }