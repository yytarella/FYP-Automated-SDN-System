import joblib
import numpy as np
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

        self.executor = ThreadPoolExecutor(max_workers=3)

    def infer(self, features_cd, features_ab):

        X_cd = np.array(features_cd).reshape(1, -1)
        X_ab = np.array(features_ab).reshape(1, -1)

        attack = int(self.model_cd.predict(X_cd)[0])
        behaviour = int(self.model_a.predict(X_ab)[0])
        academic = int(self.model_b.predict(X_ab)[0])

        # stability filter（关键）
        packet_count = X_cd[0][-2]
        duration = X_cd[0][-1]

        if attack == 1 and (packet_count < 100 or duration < 5.0):
            attack = 0

        return {
            "attack": attack,
            "behaviour": behaviour,
            "academic": academic
        }