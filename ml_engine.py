import joblib
import numpy as np
import logging
import warnings
from concurrent.futures import ThreadPoolExecutor

warnings.filterwarnings("ignore", category=UserWarning)

logger = logging.getLogger(__name__)


class MLEngine:

    def __init__(self, model_dir="models"):

        self.model_cd = joblib.load(f"{model_dir}/tier1cd_xgb_model.pkl")

        bundle_a = joblib.load(f"{model_dir}/tier1a_behaviour_rf_model.pkl")
        bundle_b = joblib.load(f"{model_dir}/tier1b_academic_rf_model.pkl")

        self.model_a = bundle_a["model"]
        self.model_b = bundle_b["model"]

        self.executor = ThreadPoolExecutor(max_workers=3)

        logger.info("ML Engine initialized (stable version)")

    def infer(self, features_cd, features_ab):

        try:
            X_cd = np.array(features_cd).reshape(1, -1)
            X_ab = np.array(features_ab).reshape(1, -1)

            future_cd = self.executor.submit(self.model_cd.predict, X_cd)
            future_a = self.executor.submit(self.model_a.predict, X_ab)
            future_b = self.executor.submit(self.model_b.predict, X_ab)

            attack = int(future_cd.result()[0])
            behaviour = int(future_a.result()[0])
            academic = int(future_b.result()[0])

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