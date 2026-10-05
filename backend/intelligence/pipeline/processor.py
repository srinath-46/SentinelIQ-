import logging
import asyncio
from typing import Dict, Any, List

from pipeline.kafka.consumer import EventConsumer
from pipeline.kafka.producer import EventProducer
from pipeline.kafka.topics import KafkaTopic
from app.services.elasticsearch import ElasticsearchService
from app.core.event_types import DataClassification
from intelligence.nlp.pii_analyzer import PIIAnalyzer
from intelligence.ml.anomaly_detector import AnomalyDetector
from intelligence.ml.classifier import ThreatClassifier

logger = logging.getLogger(__name__)

class IntelligenceProcessor:
    """
    Core ML/Intelligence ingestion pipeline.
    Consumes raw events, enriches them, and determines alerting thresholds.
    """
    
    def __init__(
        self,
        consumer: EventConsumer,
        producer: EventProducer,
        es_service: ElasticsearchService,
        alert_threshold: str = "high"
    ):
        self.consumer = consumer
        self.producer = producer
        self.es_service = es_service
        self.pii_analyzer = PIIAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.classifier = ThreatClassifier()
        
        # Mapping severities to numeric scores for easy thresholding
        self.severity_map = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        self.alert_threshold_score = self.severity_map.get(alert_threshold, 3)

    def _enrich_reputation_scoring(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Stub: Check external threat intelligence for IPs/domains."""
        event.setdefault("metadata", {})
        # Stub implementation
        event["metadata"]["threat_intel_score"] = 0
        return event

    def _enrich_historical_baseline(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Stub: Compare against user/device baseline (UEBA)."""
        event.setdefault("metadata", {})
        # Stub implementation
        event["metadata"]["ueba_anomaly_score"] = 0.0
        return event

    def _extract_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Stub: Extract numeric features for XGBoost/Isolation Forest."""
        # e.g., hour of day, byte ratio, port category
        return event

    async def _process_event(self, event: Dict[str, Any]):
        """Main processing pipeline for a single event."""
        organization_id = event.get("organization_id")
        if not organization_id:
            logger.warning("Event missing organization_id. Discarding.")
            return

        # 1. Enrichment
        event = self._enrich_reputation_scoring(event)
        
        # ML Anomaly Detection (UEBA)
        is_anomaly, score = self.anomaly_detector.predict(organization_id, event)
        event.setdefault("metadata", {})
        event["metadata"]["ueba_anomaly_score"] = score
        event["metadata"]["is_ml_anomaly"] = is_anomaly
        if is_anomaly:
            # Optionally bump severity based on deep ML outlier
            if event.get("severity", "low") in ["low", "medium"]:
                event["severity"] = "high"
                event["metadata"]["upgraded_by_intelligence"] = True
                
        # XGBoost Supervised Threat Classification
        predicted_threat, confidence = self.classifier.predict(event)
        event["metadata"]["predicted_threat_class"] = predicted_threat
        event["metadata"]["threat_confidence"] = confidence
        
        if predicted_threat != "benign" and confidence > 0.8:
            if event.get("severity", "low") in ["low", "medium", "high"]:
                event["severity"] = "critical"
                event["metadata"]["upgraded_by_supervised_ml"] = True
                event["metadata"]["ml_escalation_reason"] = f"High confidence ({confidence}) of {predicted_threat}"

        # 1.5 NLP DLP Scanning
        raw_event = event.get("raw_event", {})
        if raw_event:
            pii_scan = self.pii_analyzer.scan_event_payload(raw_event)
            if pii_scan:
                # Upgrade event data classification
                event["data_classification"] = DataClassification.pii.value
                event.setdefault("metadata", {})
                event["metadata"]["pii_scan_results"] = pii_scan

        # 2. Persistence (Elasticsearch for searchability)
        # Note: In a heavily optimized pipeline, ES writes might be bulked asynchronously,
        # but for Phase 15 we map it directly or rely on Logstash. If using Python:
        await self.es_service.index_event(organization_id, event)

        # 3. Publish to ENRICHED_EVENTS for the Detection Engine
        await self.producer.send_event(
            topic=KafkaTopic.ENRICHED_EVENTS,
            event_data=event,
            partition_key=organization_id,
            correlation_id=event.get("correlation_id")
        )

    async def start(self):
        """Start consuming and processing events."""
        logger.info("Intelligence Processor starting...")
        
        # We start the consumer with our processing callback
        # The consumer handles the continuous while-loop internally.
        await self.consumer.consume(self._process_event)


if __name__ == "__main__":
    import asyncio
    import os
    from pipeline.kafka.producer import EventProducer
    from pipeline.kafka.topics import KafkaTopic
    from app.services.elasticsearch import ElasticsearchService

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    async def main():
        bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
        es_url = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")

        dlq_producer = EventProducer(bootstrap_servers=bootstrap)
        await dlq_producer.start()

        consumer = EventConsumer(
            topics=[KafkaTopic.SECURITY_EVENTS, KafkaTopic.ENDPOINT_EVENTS, KafkaTopic.NETWORK_EVENTS],
            group_id="intelligence-processor",
            dlq_producer=dlq_producer,
            bootstrap_servers=bootstrap,
        )
        await consumer.start()

        producer = EventProducer(bootstrap_servers=bootstrap)
        await producer.start()

        es_service = ElasticsearchService(es_url=es_url)

        processor = IntelligenceProcessor(
            consumer=consumer,
            producer=producer,
            es_service=es_service,
        )

        try:
            await processor.start()
        finally:
            await consumer.stop()
            await producer.stop()
            await dlq_producer.stop()
            await es_service.close()
            logger.info("Intelligence Processor shut down.")

    asyncio.run(main())
