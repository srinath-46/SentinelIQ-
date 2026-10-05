import os
import joblib
import logging
from typing import Dict, Any, Tuple, List
import numpy as np

# We'll use sklearn's interface for xgboost for typing simplicity,
# but stub the actual implementation since training supervised models
# requires vast amounts of labeled data.
try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("xgboost not installed, using mock classifier.")

logger = logging.getLogger(__name__)

class ThreatClassifier:
    """
    Supervised ML Classifier using XGBoost.
    Identifies specific known threat categories (exfiltration, lateral movement, etc.)
    based on labeled training data.
    """
    
    def __init__(self, model_path: str = "./models/xgboost_threat_classifier.joblib"):
        self.model_path = model_path
        self.model = None
        self.classes = [
            "benign", 
            "data_exfiltration", 
            "credential_stuffing", 
            "lateral_movement", 
            "ransomware_behavior"
        ]
        self._load_model()

    def _load_model(self):
        """Load the XGBoost model from disk, or mock it if unavailable."""
        if os.path.exists(self.model_path) and XGB_AVAILABLE:
            try:
                self.model = joblib.load(self.model_path)
                logger.info("XGBoost Threat Classifier loaded successfully.")
                return
            except Exception as e:
                logger.error(f"Failed to load XGBoost model: {e}")
                
        # If no model exists or xgboost isn't installed, stub it
        self.model = None
        logger.info("XGBoost model not found or unavailable. Using stub classifier.")

    def extract_features(self, event: Dict[str, Any]) -> List[float]:
        """
        Extract numeric features for XGBoost.
        Matches the general architecture of the Isolation Forest but 
        can include categorized textual embeddings (like process names).
        """
        # Feature 1: bytes_out ratio
        b_in = event.get("bytes_in") or 0
        b_out = event.get("bytes_out") or 0
        total_bytes = b_in + b_out
        f1 = float(b_out) / total_bytes if total_bytes > 0 else 0.0
        
        # Feature 2: severity numeric mapping
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        f2 = float(severity_map.get(event.get("severity", "low").lower(), 1))
        
        # Feature 3: Action numeric mapping (mocked)
        action_map = {"allow": 0, "deny": 1, "alert": 2}
        f3 = float(action_map.get(event.get("action", "allow").lower(), 0))
        
        return [f1, f2, f3]

    def predict(self, event: Dict[str, Any]) -> Tuple[str, float]:
        """
        Predict the specific threat category and confidence probability.
        """
        vector = self.extract_features(event)
        
        if self.model and XGB_AVAILABLE:
            X = np.array([vector])
            # XGBClassifier returns probabilities for each class
            probas = self.model.predict_proba(X)[0]
            max_idx = np.argmax(probas)
            predicted_class = self.classes[max_idx]
            confidence = float(probas[max_idx])
        else:
            # Stub logic for demonstration
            # High byte_out ratio -> data exfiltration mock
            if vector[0] > 0.9 and vector[1] > 2:
                predicted_class = "data_exfiltration"
                confidence = 0.85
            elif vector[1] > 3:
                # High severity fallback
                predicted_class = "lateral_movement"
                confidence = 0.72
            else:
                predicted_class = "benign"
                confidence = 0.99

        return predicted_class, confidence
