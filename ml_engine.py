import joblib
import numpy as np
import pandas as pd
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class MLEngine:

    def __init__(self, model_dir="models"):

        # CD model (XGBoost)
        self.model_cd = joblib.load(f"{model_dir}/tier1cd_xgb_model.pkl")

        # AB models (RandomForest)
        bundle_a = joblib.load(f"{model_dir}/tier1a_behaviour_rf_model.pkl")
        bundle_b = joblib.load(f"{model_dir}/tier1b_academic_rf_model.pkl")

        self.model_a = bundle_a["model"]
        self.model_b = bundle_b["model"]

        # IMPORTANT: feature names from training
        self.feature_names = bundle_a["features"]

        self.executor = ThreadPoolExecutor(max_workers=3)

        logger.info(f"ML Engine initialized | AB features = {len(self.feature_names)}")

    def infer(self, features_cd, features_ab):

        try:
            # CD (attack) → numpy (correct)
            X_cd = np.array(features_cd).reshape(1, -1)

            # AB → MUST use DataFrame
            X_ab = pd.DataFrame([features_ab], columns=self.feature_names)

            # parallel execution
            future_cd = self.executor.submit(self.model_cd.predict, X_cd)
            future_a = self.executor.submit(self.model_a.predict, X_ab)
            future_b = self.executor.submit(self.model_b.predict, X_ab)

            attack = int(future_cd.result()[0])
            behaviour = int(future_a.result()[0])
            academic = int(future_b.result()[0])

            # stability filter (prevent early false positives)
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