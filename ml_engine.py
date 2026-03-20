import joblib
import numpy as np
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class MLEngine:

    def __init__(self, model_dir="models"):
        self.model_cd = joblib.load(f"{model_dir}/tier1cd_xgb_model.pkl")
        self.model_a = joblib.load(f"{model_dir}/tier1a_behaviour_rf_model.pkl")
        self.model_b = joblib.load(f"{model_dir}/tier1b_academic_rf_model.pkl")

        self.executor = ThreadPoolExecutor(max_workers=3)

        logger.info("Models loaded (parallel inference enabled)")

    def _predict_cd(self, features):
        return self.model_cd.predict(features)[0]

    def _predict_a(self, features):
        return self.model_a.predict(features)[0]

    def _predict_b(self, features):
        return self.model_b.predict(features)[0]

    def infer(self, features):

        features = np.array(features).reshape(1, -1)

        # parallel execution
        future_cd = self.executor.submit(self._predict_cd, features)
        future_a = self.executor.submit(self._predict_a, features)
        future_b = self.executor.submit(self._predict_b, features)

        # security first
        attack = future_cd.result()

        if attack == 1:
            logger.warning("Attack detected - immediate block")
            return {
                "attack": 1,
                "behaviour": None,
                "academic": None
            }

        behaviour = future_a.result()
        academic = future_b.result()

        return {
            "attack": 0,
            "behaviour": behaviour,
            "academic": academic
        }