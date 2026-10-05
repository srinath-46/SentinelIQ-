import logging
import asyncio
from typing import Dict, Any, List
from datetime import datetime, timezone
from uuid import uuid4

from pipeline.kafka.consumer import EventConsumer
from pipeline.kafka.producer import EventProducer
from pipeline.kafka.topics import KafkaTopic
from app.db.session import AsyncSessionLocal
from app.db.base import Base  # ensures all models are loaded
from app.models.detection_rule import DetectionRule
from sqlalchemy.future import select

from detection.engine.evaluator import RuleEvaluator
from detection.engine.correlator import CorrelationEngine

logger = logging.getLogger(__name__)

class DetectionProcessor:
    """
    Core Detection Pipeline.
    Consumes ENRICHED_EVENTS, evaluates active detection rules,
    runs correlation logic, and generates DETECTIONS (Detection Findings).
    """
    
    def __init__(
        self,
        consumer: EventConsumer,
        producer: EventProducer,
        redis_url: str
    ):
        self.consumer = consumer
        self.producer = producer
        self.correlator = CorrelationEngine(redis_url=redis_url)
        
        # Cache for rules to avoid hitting DB per event
        # In production this would be periodically refreshed
        self._rules_cache: List[DetectionRule] = []
        self._last_rules_refresh: float = 0.0
        self._rules_refresh_interval = 60 # seconds
        
    async def _refresh_rules_if_needed(self):
        now = asyncio.get_event_loop().time()
        if now - self._last_rules_refresh > self._rules_refresh_interval:
            await self._refresh_rules()
            self._last_rules_refresh = now
            
    async def _refresh_rules(self):
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(DetectionRule).where(
                        DetectionRule.enabled == True,
                        DetectionRule.lifecycle_state == "ACTIVE"
                    )
                )
                self._rules_cache = list(result.scalars().all())
                logger.info(f"Refreshed detection rules cache. Loaded {len(self._rules_cache)} active rules.")
        except Exception as e:
            logger.error(f"Failed to refresh rules from database: {e}")

    async def _process_event(self, event: Dict[str, Any]):
        """Main processing pipeline for a single event."""
        organization_id = event.get("organization_id")
        if not organization_id:
            return

        await self._refresh_rules_if_needed()
        
        for rule in self._rules_cache:
            # Check tenant isolation - system rules (org_id is null) apply to all, else must match
            if rule.organization_id is not None and str(rule.organization_id) != str(organization_id):
                continue
                
            # Quick check on required event types
            if rule.required_event_types:
                if event.get("event_type") not in rule.required_event_types:
                    continue
                    
            # 1. Evaluate Rule Conditions
            try:
                matched = RuleEvaluator.evaluate(event, rule.conditions) # type: ignore
            except Exception as e:
                logger.error(f"Rule evaluation failed for rule {rule.id}: {e}")
                continue
                
            if matched:
                # 2. Stateful Correlation, Thresholds, Deduplication
                try:
                    should_alert = await self.correlator.process(rule, event)
                except Exception as e:
                    logger.error(f"Correlation failed for rule {rule.id}: {e}")
                    should_alert = True # Fail open to ensure we don't miss alerts
                    
                if should_alert:
                    # 3. Generate Detection Finding
                    finding = {
                        "id": str(uuid4()),
                        "organization_id": organization_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "rule_id": str(rule.id),
                        "rule_version": rule.version,
                        "rule_name": rule.name,
                        "severity": rule.severity,
                        "category": rule.category,
                        "subcategory": rule.subcategory,
                        "mitre_attack_techniques": rule.mitre_attack_techniques,
                        "triggering_event": event,
                        "status": "NEW"
                    }
                    
                    # 4. Publish to DETECTIONS topic
                    logger.info(f"Detection finding generated for rule '{rule.name}' on org {organization_id}")
                    await self.producer.send_event(
                        topic=KafkaTopic.DETECTIONS,
                        event_data=finding,
                        partition_key=organization_id,
                        correlation_id=event.get("correlation_id")
                    )

    async def start(self):
        """Start consuming and processing events."""
        logger.info("Detection Processor starting...")
        await self._refresh_rules()
        await self.consumer.consume(self._process_event)


if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    async def main():
        bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
        redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/1")

        dlq_producer = EventProducer(bootstrap_servers=bootstrap)
        await dlq_producer.start()

        consumer = EventConsumer(
            topics=[KafkaTopic.ENRICHED_EVENTS],
            group_id="detection-engine",
            dlq_producer=dlq_producer,
            bootstrap_servers=bootstrap,
        )
        await consumer.start()

        producer = EventProducer(bootstrap_servers=bootstrap)
        await producer.start()

        processor = DetectionProcessor(
            consumer=consumer,
            producer=producer,
            redis_url=redis_url
        )

        try:
            await processor.start()
        finally:
            await consumer.stop()
            await producer.stop()
            await dlq_producer.stop()
            await processor.correlator.close()
            logger.info("Detection Processor shut down.")

    asyncio.run(main())
