import joblib
import numpy as np
import pandas as pd
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class MLEngine:

    def __init__(self, model_dir="models"):

        self.model_cd = joblib.load(f"{model_dir}/tier1cd_xgb_model.pkl")

        bundle_a = joblib.load(f"{model_dir}/tier1a_behaviour_rf_model.pkl")
        bundle_b = joblib.load(f"{model_dir}/tier1b_academic_rf_model.pkl")

        self.model_a = bundle_a["model"]
        self.model_b = bundle_b["model"]

        self.feature_names = bundle_a["features"]

        self.executor = ThreadPoolExecutor(max_workers=3)

        logger.info(f"ML Engine initialized | AB features = {len(self.feature_names)}")

    def safe_ratio(self, a, b):
        return 0 if b == 0 else a / b

    def add_ratio_features(self, features_ab):
        """
        features_ab = 40 features
        we add:
        - pl_mean_ratio
        - iat_ratio
        - pps_ratio
        """

        # index mapping based on your dataset order

        # forward_pl_mean = index 11
        # reverse_pl_mean = index 31
        pl_ratio = self.safe_ratio(features_ab[11], features_ab[31])

        # forward_piat_mean = index 5
        # reverse_piat_mean = index 25
        iat_ratio = self.safe_ratio(features_ab[5], features_ab[25])

        # forward_pps_mean = index 17
        # reverse_pps_mean = index 37
        pps_ratio = self.safe_ratio(features_ab[17], features_ab[37])

        return features_ab + [pl_ratio, iat_ratio, pps_ratio]

    def infer(self, features_cd, features_ab):

        try:
            # CD model
            X_cd = np.array(features_cd).reshape(1, -1)

            # FIX: add missing 3 features
            features_ab_full = self.add_ratio_features(features_ab)

            if len(features_ab_full) != len(self.feature_names):
                logger.error(
                    f"Feature mismatch: got {len(features_ab_full)}, expected {len(self.feature_names)}"
                )
                return {
                    "attack": 0,
                    "behaviour": -1,
                    "academic": -1
                }

            X_ab = pd.DataFrame([features_ab_full], columns=self.feature_names)

            future_cd = self.executor.submit(self.model_cd.predict, X_cd)
            future_a = self.executor.submit(self.model_a.predict, X_ab)
            future_b = self.executor.submit(self.model_b.predict, X_ab)

            attack = int(future_cd.result()[0])
            behaviour = int(future_a.result()[0])
            academic = int(future_b.result()[0])

            # stability filter
            packet_count = X_cd[0][-2]
            duration = X_cd[0][-1]

            if attack == 1:
                if packet_count < 100 or duration < 5.0:
                    attack = 0

            logger.info(
                f"[ML] attack={attack}, behaviour={behaviour}, academic={academic}"
            )

            return {
                "attack": attack,
                "behaviour": behaviour,
                "academic": academic
            }

        except Exception as e:
            logger.error(f"ML error: {e}")

            return {
                "attack": 0,
                "behaviour": -1,
                "academic": -1
            }