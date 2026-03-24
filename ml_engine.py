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

        logger.info(f"Expected feature count: {len(self.feature_names)}")

    def infer(self, features_cd, features_ab):

        try:
            if len(features_ab) != len(self.feature_names):
                logger.error(
                    f"Feature length mismatch: got {len(features_ab)}, expected {len(self.feature_names)}"
                )
                return {
                    "attack": 0,
                    "behaviour": -1,
                    "academic": -1
                }

            X_cd = np.array(features_cd).reshape(1, -1)

            X_ab = pd.DataFrame([features_ab], columns=self.feature_names)

            attack = int(self.model_cd.predict(X_cd)[0])
            behaviour = int(self.model_a.predict(X_ab)[0])
            academic = int(self.model_b.predict(X_ab)[0])

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