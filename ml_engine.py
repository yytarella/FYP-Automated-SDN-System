import joblib
import numpy as np
import pandas as pd
import logging
import warnings
from concurrent.futures import ThreadPoolExecutor

warnings.filterwarnings("ignore", category=UserWarning)

logger = logging.getLogger(__name__)


class MLEngine:

    def __init__(self, model_dir="models"):

        self.bundle_cd = joblib.load(f"{model_dir}/tier1cd_xgb_model.pkl")
        self.bundle_a = joblib.load(f"{model_dir}/tier1a_behaviour_rf_model.pkl")
        self.bundle_b = joblib.load(f"{model_dir}/tier1b_academic_rf_model.pkl")

        self.model_cd = self._extract_model(self.bundle_cd)
        self.model_a = self._extract_model(self.bundle_a)
        self.model_b = self._extract_model(self.bundle_b)

        self.features_a = self.bundle_a.get("features", [])
        self.features_b = self.bundle_b.get("features", [])

        self.executor = ThreadPoolExecutor(max_workers=3)

        logger.info("ML Engine initialized with feature alignment")

    def _extract_model(self, obj):
        if isinstance(obj, dict):
            return obj.get("model", list(obj.values())[0])
        return obj

    def _safe_ratio(self, a, b):
        return np.where(b == 0, 0, a / b)

    def _build_dataframe_ab(self, raw_features):

        data = {
            "forward_pl_mean": raw_features[0],
            "forward_pl_var": raw_features[1],
            "forward_pl_min": raw_features[2],
            "forward_pl_max": raw_features[3],
            "forward_pl_q1": raw_features[4],
            "forward_pl_q3": raw_features[5],

            "forward_piat_mean": raw_features[6],
            "forward_piat_var": raw_features[7],
            "forward_piat_min": raw_features[8],
            "forward_piat_max": raw_features[9],
            "forward_piat_q1": raw_features[10],
            "forward_piat_q3": raw_features[11],

            "forward_pps_mean": raw_features[15],

            "reverse_pl_mean": raw_features[18],
            "reverse_piat_mean": raw_features[24],
            "reverse_pps_mean": raw_features[33],
        }

        row = {}
        for col in self.features_a:
            row[col] = data.get(col, 0)

        df = pd.DataFrame([row])

        if "pl_mean_ratio" in df.columns:
            df["pl_mean_ratio"] = self._safe_ratio(
                df["forward_pl_mean"],
                df["reverse_pl_mean"]
            )

        if "iat_ratio" in df.columns:
            df["iat_ratio"] = self._safe_ratio(
                df["forward_piat_mean"],
                df["reverse_piat_mean"]
            )

        if "pps_ratio" in df.columns:
            df["pps_ratio"] = self._safe_ratio(
                df["forward_pps_mean"],
                df["reverse_pps_mean"]
            )

        return df[self.features_a]

    def infer(self, features_cd, features_ab):

        try:
            X_cd = np.array(features_cd).reshape(1, -1)
            X_ab_df = self._build_dataframe_ab(features_ab)

            future_cd = self.executor.submit(self.model_cd.predict, X_cd)
            future_a = self.executor.submit(self.model_a.predict, X_ab_df)
            future_b = self.executor.submit(self.model_b.predict, X_ab_df)

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