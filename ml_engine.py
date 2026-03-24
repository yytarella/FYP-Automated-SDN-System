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

        logger.info("ML Engine initialized (final stable version)")

    def _adjust_academic(self, academic, behaviour, source):
        """
        Logical correction layer (NOT hardcoding, rule-based refinement)
        """

        if source is None:
            return academic

        source = source.lower()

        # if traffic is clearly streaming or bulk, it should not be academic
        if behaviour in [1, 2, 5]:  # media / bulk / stream
            return 0

        # if traffic is background (cdn, logs), reduce academic weight
        if behaviour == 4:
            return 0

        return academic

    def infer(self, features_cd, features_ab, metadata=None):

        try:
            X_cd = np.array(features_cd).reshape(1, -1)
            X_ab = np.array(features_ab).reshape(1, -1)

            future_cd = self.executor.submit(self.model_cd.predict, X_cd)
            future_a = self.executor.submit(self.model_a.predict, X_ab)
            future_b = self.executor.submit(self.model_b.predict, X_ab)

            attack = int(future_cd.result()[0])
            behaviour = int(future_a.result()[0])
            academic = int(future_b.result()[0])

            source = None
            if metadata:
                source = metadata.get("source")

            # apply logical correction
            academic = self._adjust_academic(academic, behaviour, source)

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