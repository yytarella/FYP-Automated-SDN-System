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

    def _sanity_check(self, X, name):
        """
        Validate feature quality before inference
        """
        if np.isnan(X).any():
            logger.error(f"{name} contains NaN")
            return False

        if np.isinf(X).any():
            logger.error(f"{name} contains Inf")
            return False

        # check extreme values
        if np.max(np.abs(X)) > 1e6:
            logger.warning(f"{name} has extreme values: max={np.max(np.abs(X))}")

        return True

    def infer(self, features_cd, features_ab):

        try:
            X_cd = np.array(features_cd, dtype=float).reshape(1, -1)
            X_ab = np.array(features_ab, dtype=float).reshape(1, -1)

            # shape check (no padding anymore)
            if self.expected_cd and X_cd.shape[1] != self.expected_cd:
                logger.error(f"CD feature mismatch: got {X_cd.shape[1]}, expected {self.expected_cd}")
                return {"attack": 0, "behaviour": -1, "academic": -1}

            if self.expected_a and X_ab.shape[1] != self.expected_a:
                logger.error(f"AB feature mismatch: got {X_ab.shape[1]}, expected {self.expected_a}")
                return {"attack": 0, "behaviour": -1, "academic": -1}

            # sanity check (NEW)
            if not self._sanity_check(X_cd, "CD"):
                return {"attack": 0, "behaviour": -1, "academic": -1}

            if not self._sanity_check(X_ab, "AB"):
                return {"attack": 0, "behaviour": -1, "academic": -1}

            # DEBUG (you NEED this now)
            logger.info(f"[DEBUG] CD first5={X_cd[0][:5]}")
            logger.info(f"[DEBUG] AB first5={X_ab[0][:5]}")
            logger.info(f"[DEBUG] packet_count={X_cd[0][-2]}, duration={X_cd[0][-1]}")

            future_cd = self.executor.submit(self.model_cd.predict, X_cd)
            future_a = self.executor.submit(self.model_a.predict, X_ab)
            future_b = self.executor.submit(self.model_b.predict, X_ab)

            attack = future_cd.result()[0]

            # stability gating (keep your logic)
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
                "attack": int(attack),
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