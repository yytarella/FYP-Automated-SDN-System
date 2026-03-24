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

        self.model_cd = self._extract_model(self.model_cd)
        self.model_a = self._extract_model(self.model_a)
        self.model_b = self._extract_model(self.model_b)

        self.expected_cd = getattr(self.model_cd, "n_features_in_", None)
        self.expected_a = getattr(self.model_a, "n_features_in_", None)
        self.expected_b = getattr(self.model_b, "n_features_in_", None)

        self.executor = ThreadPoolExecutor(max_workers=3)

        logger.info(f"Expected features CD={self.expected_cd}, A={self.expected_a}, B={self.expected_b}")

    def _extract_model(self, obj):
        if isinstance(obj, dict):
            for key in ["model", "classifier", "clf"]:
                if key in obj:
                    return obj[key]
            return list(obj.values())[0]
        return obj

    def _align(self, features, expected):
        if expected is None:
            return features

        if features.shape[1] < expected:
            features = np.pad(features, ((0, 0), (0, expected - features.shape[1])), mode='constant')
        elif features.shape[1] > expected:
            features = features[:, :expected]

        return features

    def infer(self, features_cd, features_ab):

        try:
            X_cd = np.array(features_cd).reshape(1, -1)
            X_ab = np.array(features_ab).reshape(1, -1)

            X_cd = self._align(X_cd, self.expected_cd)
            X_ab = self._align(X_ab, self.expected_a)

            future_cd = self.executor.submit(self.model_cd.predict, X_cd)
            future_a = self.executor.submit(self.model_a.predict, X_ab)
            future_b = self.executor.submit(self.model_b.predict, X_ab)

            attack = future_cd.result()[0]

            # stability gating
            packet_count = X_cd[0][-2]
            duration = X_cd[0][-1]

            if attack == 1:
                if packet_count < 30 or duration < 1.0:
                    attack = 0
                else:
                    logger.warning("Attack confirmed")

            behaviour = future_a.result()[0]
            academic = future_b.result()[0]

            logger.info(f"[ML] attack={attack}, behaviour={behaviour}, academic={academic}")

            return {
                "attack": attack,
                "behaviour": str(behaviour).lower(),
                "academic": int(academic)
            }

        except Exception as e:
            logger.error(f"ML error: {e}")

            return {
                "attack": 0,
                "behaviour": -1,
                "academic": -1
            }