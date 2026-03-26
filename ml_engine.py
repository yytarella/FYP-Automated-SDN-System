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
            self.feature_names = bundle_a["features"]
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
            # build tier1cd vector
            X_cd = np.array([[features_cd_dict.get(name, 0) for name in self.feature_names_cd]])

            # compute ratio features
            pl_ratio = self.safe_ratio(features_ab_dict.get("forward_pl_mean", 0),
                                       features_ab_dict.get("reverse_pl_mean", 0))
            iat_ratio = self.safe_ratio(features_ab_dict.get("forward_piat_mean", 0),
                                        features_ab_dict.get("reverse_piat_mean", 0))
            pps_ratio = self.safe_ratio(features_ab_dict.get("forward_pps_mean", 0),
                                        features_ab_dict.get("reverse_pps_mean", 0))

            features_ab_dict["pl_mean_ratio"] = pl_ratio
            features_ab_dict["iat_ratio"] = iat_ratio
            features_ab_dict["pps_ratio"] = pps_ratio

            # build tier1ab DataFrame
            X_ab = pd.DataFrame([[features_ab_dict.get(name, 0) for name in self.feature_names]],
                                columns=self.feature_names)

            # parallel inference
            f_cd_proba = self.executor.submit(self.model_cd.predict_proba, X_cd)
            f_a = self.executor.submit(self.model_a.predict, X_ab)
            f_b = self.executor.submit(self.model_b.predict, X_ab)

            attack_probs = f_cd_proba.result()[0]
            attack_confidence = attack_probs[1] if len(attack_probs) > 1 else 0

            raw_behaviour = int(f_a.result()[0])
            raw_academic = int(f_b.result()[0])

            # decode labels
            if self.label_encoder_a is not None:
                behaviour_label = self.label_encoder_a.inverse_transform([raw_behaviour])[0]
            else:
                behaviour_label = self.behaviour_map.get(raw_behaviour, "unknown")

            if self.label_encoder_b is not None:
                academic_label = self.label_encoder_b.inverse_transform([raw_academic])[0]
                academic = 1 if academic_label == "academic" else 0
            else:
                academic = 1 if raw_academic == 0 else 0   # fallback

            packet_count = features_cd_dict.get("packet_count", 0)
            final_attack = 0

            # base attack detection (strict)
            if attack_confidence > 0.95 and packet_count > 50:
                final_attack = 1

            # post-processing rules (to reduce false positives)
            domain = metadata.get("source", "") if metadata else ""
            domain_lower = domain.lower() if domain else ""

            # 1. if domain is in safe list, force attack = 0 and academic = 0
            safe_domains = ['google', 'youtube', 'github', 'ieee', 'springer', 'sciencedirect', 
                            'researchgate', 'stackoverflow', 'w3schools', 'coursera', 'zoom', 'teams']
            if any(sd in domain_lower for sd in safe_domains):
                if final_attack == 1:
                    logger.info(f"[ML] Override attack=1 -> 0 for safe domain: {domain}")
                    final_attack = 0
                # for safe domains, keep academic as is (they might be academic sites)
                # if to reduce priority for non-academic safe domains, set academic = 0
                # final leave to policy engine to decide

            # 2. If domain is unknown (IP address) and ML says academic = 1, force academic = 0
            if (not domain or domain == "unknown") and academic == 1:
                logger.info(f"[ML] Override academic=1 -> 0 for unknown IP flow")
                academic = 0

            # 3. if packet count is lower than 30, reduce attack confidence (already covered by threshold)
            # 4. if confidence is moderate but attack flag is set, double-check with behaviour
            if final_attack == 1 and attack_confidence < 0.98 and packet_count < 100:
                logger.info(f"[ML] Suppress attack due to moderate confidence and low packets: conf={attack_confidence:.2f}, pkts={packet_count}")
                final_attack = 0

            # 5. if behaviour is "media" or "chat" and academic = 1 but domain doesnt look academic, force academic = 0
            # prevent streaming from getting academic priority
            if academic == 1 and behaviour_label in ["media", "chat"]:
                # check if domain contains academic keywords (simple list)
                academic_keywords = ['.edu', 'ieee', 'springer', 'sciencedirect', 'researchgate', 'scholar', 'arxiv', 'coursera']
                if not any(kw in domain_lower for kw in academic_keywords):
                    logger.info(f"[ML] Override academic=1 -> 0 for media/chat flow without academic domain: {domain}")
                    academic = 0

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