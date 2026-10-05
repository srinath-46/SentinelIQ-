import logging
from typing import Dict, Any, List, Optional
from functools import lru_cache
import hashlib

# Attempt to import presidio, fail gracefully if not installed in this environment yet
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerResult
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

logger = logging.getLogger(__name__)

class PIIAnalyzer:
    """
    Microsoft Presidio-backed NLP analyzer for detecting Data Loss (DLP).
    Detects PII/Secrets in textual events (chats, emails, documents).
    """
    def __init__(self):
        self.analyzer = AnalyzerEngine() if PRESIDIO_AVAILABLE else None
        self.anonymizer = AnonymizerEngine() if PRESIDIO_AVAILABLE else None
        
        # Entities we explicitly care about for DLP
        self.entities = [
            "CREDIT_CARD",
            "US_SSN",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CRYPTO",
            "IBAN_CODE",
            "IP_ADDRESS"
        ]

    def _hash_text(self, text: str) -> str:
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    @lru_cache(maxsize=1000)
    def _analyze_text_cached(self, text_hash: str, text: str) -> List[Any]:
        """Cached wrapper to prevent re-analyzing identical strings repeatedly."""
        if not self.analyzer:
            return []
        return self.analyzer.analyze(text=text, entities=self.entities, language='en')

    def analyze_and_anonymize(self, text: str) -> Dict[str, Any]:
        """
        Analyze text for PII. 
        Returns the detected entities and an anonymized version of the text.
        """
        if not text or not PRESIDIO_AVAILABLE:
            return {"contains_pii": False, "anonymized_text": text, "entities": []}

        # Use hashing for cache key to avoid massive memory footprint of raw text caching
        text_hash = self._hash_text(text)
        results = self._analyze_text_cached(text_hash, text)
        
        if not results:
            return {"contains_pii": False, "anonymized_text": text, "entities": []}

        # Mask found entities
        # By default, Presidio replaces with <ENTITY_TYPE>
        if self.anonymizer is None:
            return {"contains_pii": False, "anonymized_text": text, "entities": []}
            
        anonymized_result = self.anonymizer.anonymize(text=text, analyzer_results=results)
        
        # Extract unique entity types found
        detected_types = list({res.entity_type for res in results})
        
        return {
            "contains_pii": True,
            "anonymized_text": anonymized_result.text,
            "entities": detected_types
        }

    def scan_event_payload(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scans common text fields in a raw event for PII.
        """
        pii_results = {}
        fields_to_scan = ["message", "full_log", "description", "body", "content"]
        
        for field in fields_to_scan:
            val = raw_event.get(field)
            if val and isinstance(val, str):
                res = self.analyze_and_anonymize(val)
                if res["contains_pii"]:
                    pii_results[field] = res
                    
        return pii_results
