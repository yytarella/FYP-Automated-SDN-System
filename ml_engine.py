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

        # Extract actual models if wrapped in dict
        self.model_cd = self._extract_model(self.model_cd, "CD")
        self.model_a = self._extract_model(self.model_a, "A")
        self.model_b = self._extract_model(self.model_b, "B")

        # Expected feature sizes
        self.expected_cd = getattr(self.model_cd, "n_features_in_", None)
        self.expected_a = getattr(self.model_a, "n_features_in_", None)
        self.expected_b = getattr(self.model_b, "n_features_in_", None)

        logger.info(f"Expected features → CD={self.expected_cd}, A={self.expected_a}, B={self.expected_b}")

        self.executor = ThreadPoolExecutor(max_workers=3)

        logger.info("Models loaded (parallel inference enabled)")

    def _extract_model(self, obj, name):
        if isinstance(obj, dict):
            logger.warning(f"{name} model loaded as dict, extracting actual model...")

            for key in ["model", "classifier", "clf"]:
                if key in obj:
                    logger.info(f"{name} model extracted using key: {key}")
                    return obj[key]

            logger.warning(f"{name} model key unknown, using first value")
            return list(obj.values())[0]

        return obj

    def _align_features(self, features, expected):
        if expected is None:
            return features

        current = features.shape[1]

        if current < expected:
            logger.warning(f"Padding features {current} → {expected}")
            features = np.pad(features, ((0, 0), (0, expected - current)), mode='constant')

        elif current > expected:
            logger.warning(f"Trimming features {current} → {expected}")
            features = features[:, :expected]

        return features

    def _predict_cd(self, features):
        try:
            features = self._align_features(features, self.expected_cd)
            return self.model_cd.predict(features)[0]
        except Exception as e:
            logger.error(f"CD prediction error: {e}")
            return 0 

    def _predict_a(self, features):
        try:
            features = self._align_features(features, self.expected_a)
            return self.model_a.predict(features)[0]
        except Exception as e:
            logger.error(f"A prediction error: {e}")
            return -1

    def _predict_b(self, features):
        try:
            features = self._align_features(features, self.expected_b)
            return self.model_b.predict(features)[0]
        except Exception as e:
            logger.error(f"B prediction error: {e}")
            return -1

    def infer(self, features):

        try:
            features = np.array(features).reshape(1, -1)

            logger.debug(f"Input feature shape: {features.shape}")

            # parallel inference
            future_cd = self.executor.submit(self._predict_cd, features)
            future_a = self.executor.submit(self._predict_a, features)
            future_b = self.executor.submit(self._predict_b, features)

            attack = future_cd.result()

            logger.debug(f"Attack prediction: {attack}")

            if attack == 1:
                logger.warning("Attack detected (DEBUG MODE - not blocking)")
                attack = 0

            behaviour = future_a.result()
            academic = future_b.result()

            logger.info(f"[ML] attack={attack}, behaviour={behaviour}, academic={academic}")

            return {
                "attack": attack,
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