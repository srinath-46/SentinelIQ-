import os
import joblib
import logging
from typing import List, Dict, Any, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Unsupervised ML detector using Isolation Forest.
    Maintains tenant-isolated models.
    """
    
    def __init__(self, model_storage_path: str = "./models/"):
        self.model_storage_path = model_storage_path
        os.makedirs(self.model_storage_path, exist_ok=True)
        # In-memory cache of models: { organization_id: IsolationForest }
        self._models: Dict[str, IsolationForest] = {}

    def _get_model_path(self, organization_id: str) -> str:
        return os.path.join(self.model_storage_path, f"iforest_{organization_id}.joblib")

    def _load_model(self, organization_id: str) -> IsolationForest:
        """Load from cache, then disk, or create new."""
        if organization_id in self._models:
            return self._models[organization_id]
            
        model_path = self._get_model_path(organization_id)
        if os.path.exists(model_path):
            try:
                model = joblib.load(model_path)
                self._models[organization_id] = model
                return model
            except Exception as e:
                logger.error(f"Failed to load model for {organization_id}: {e}")
                
        # Return a fresh, untrained model
        model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
        self._models[organization_id] = model
        return model

    def _save_model(self, organization_id: str, model: IsolationForest):
        """Save model to disk."""
        model_path = self._get_model_path(organization_id)
        try:
            joblib.dump(model, model_path)
            self._models[organization_id] = model
        except Exception as e:
            logger.error(f"Failed to save model for {organization_id}: {e}")

    def extract_vector(self, event: Dict[str, Any]) -> List[float]:
        """
        Extract numerical features from an event for ML scoring.
        Stub implementation. In reality, this would involve one-hot encoding,
        time-of-day extraction, byte counting, etc.
        """
        # Feature 1: bytes_in (log scaled)
        b_in = event.get("bytes_in") or 0
        f1 = np.log1p(float(b_in))
        
        # Feature 2: bytes_out (log scaled)
        b_out = event.get("bytes_out") or 0
        f2 = np.log1p(float(b_out))
        
        # Feature 3: Hour of day
        # Timestamp expected as ISO string or datetime
        ts = event.get("timestamp")
        hour = 0
        if isinstance(ts, str):
            try:
                from datetime import datetime
                # basic parsing
                hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
            except:
                pass
                
        f3 = float(hour) / 24.0
        
        return [f1, f2, f3]

    def train(self, organization_id: str, events: List[Dict[str, Any]]) -> bool:
        """
        Train/fit the Isolation Forest for a specific tenant based on historical data.
        """
        if not events:
            return False
            
        vectors = [self.extract_vector(e) for e in events]
        X = np.array(vectors)
        
        model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
        model.fit(X)
        
        self._save_model(organization_id, model)
        logger.info(f"Successfully trained Isolation Forest for tenant {organization_id} on {len(events)} events.")
        return True

    def predict(self, organization_id: str, event: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Predict if an event is anomalous.
        Returns (is_anomaly: bool, anomaly_score: float).
        Lower scores (negative) mean more anomalous.
        """
        model = self._load_model(organization_id)
        
        # sklearn IsolationForest throws NotFittedError if not trained.
        # We can detect this gracefully via a duck-typing check
        if not hasattr(model, "estimators_") or not model.estimators_:
            # Model not yet trained, return neutral baseline
            return False, 0.0
            
        vector = self.extract_vector(event)
        X = np.array([vector])
        
        prediction = model.predict(X)[0] # 1 for inlier, -1 for outlier
        score = model.score_samples(X)[0] # Negative score for anomaly
        
        is_anomaly = bool(prediction == -1)
        return is_anomaly, float(score)
