import joblib
import numpy as np
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class MLEngine:

    def __init__(self, model_dir="models"):
        # Load models
        self.model_cd = joblib.load(f"{model_dir}/tier1cd_xgb_model.pkl")
        self.model_a = joblib.load(f"{model_dir}/tier1a_behaviour_rf_model.pkl")
        self.model_b = joblib.load(f"{model_dir}/tier1b_academic_rf_model.pkl")

        # handle dict-based models
        self.model_cd = self._extract_model(self.model_cd, "CD")
        self.model_a = self._extract_model(self.model_a, "A")
        self.model_b = self._extract_model(self.model_b, "B")

        self.executor = ThreadPoolExecutor(max_workers=3)

        logger.info("Models loaded (parallel inference enabled)")

    def _extract_model(self, obj, name):
        """
        Ensure we always get the actual ML model (not dict)
        """
        if isinstance(obj, dict):
            logger.warning(f"{name} model loaded as dict, extracting actual model...")

            # Try common keys
            for key in ["model", "classifier", "clf"]:
                if key in obj:
                    logger.info(f"{name} model extracted using key: {key}")
                    return obj[key]

            # fallback: just return first value
            logger.warning(f"{name} model key unknown, using first value in dict")
            return list(obj.values())[0]

        return obj

    def _predict_cd(self, features):
        try:
            return self.model_cd.predict(features)[0]
        except Exception as e:
            logger.error(f"CD prediction error: {e}")
            return 0  # treat as non-attack instead of crashing

    def _predict_a(self, features):
        try:
            return self.model_a.predict(features)[0]
        except Exception as e:
            logger.error(f"A prediction error: {e}")
            return -1

    def _predict_b(self, features):
        try:
            return self.model_b.predict(features)[0]
        except Exception as e:
            logger.error(f"B prediction error: {e}")
            return -1

    def infer(self, features):

        try:
            features = np.array(features).reshape(1, -1)

            # For debug
            logger.debug(f"Features shape: {features.shape}")

            # parallel execution
            future_cd = self.executor.submit(self._predict_cd, features)
            future_a = self.executor.submit(self._predict_a, features)
            future_b = self.executor.submit(self._predict_b, features)

            # security first
            attack = future_cd.result()

            logger.debug(f"Attack prediction: {attack}")

            if attack == 1:
                logger.warning("Attack detected - immediate block")
                return {
                    "attack": 1,
                    "behaviour": None,
                    "academic": None
                }

            behaviour = future_a.result()
            academic = future_b.result()

            logger.info(f"Prediction → attack=0, behaviour={behaviour}, academic={academic}")

            return {
                "attack": 0,
                "behaviour": behaviour,
                "academic": academic
            }

        except Exception as e:
            logger.error(f"Pipeline error: {e}")

            return {
                "attack": 0,
                "behaviour": -1,
                "academic": -1
            }