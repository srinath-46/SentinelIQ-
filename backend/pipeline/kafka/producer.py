import json
import logging
import uuid
from typing import Any, Dict, Optional
from aiokafka import AIOKafkaProducer

from app.core.config import settings
from pipeline.kafka.topics import KafkaTopic

logger = logging.getLogger(__name__)

class EventProducer:
    """Async Kafka Producer for SentinelIQ events."""
    
    def __init__(self, bootstrap_servers: Optional[str] = None):
        self.bootstrap_servers = bootstrap_servers or settings.KAFKA_BOOTSTRAP_SERVERS
        self.producer: Optional[AIOKafkaProducer] = None
        
    async def start(self):
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
            key_serializer=lambda k: k.encode('utf-8') if k else None,
            enable_idempotence=True,  # Idempotent producer
            acks="all",
            retry_backoff_ms=500
        )
        await self.producer.start()
        logger.info(f"Kafka Producer started on {self.bootstrap_servers}")

    async def stop(self):
        if self.producer:
            await self.producer.stop()
            logger.info("Kafka Producer stopped")

    async def send_event(
        self, 
        topic: KafkaTopic, 
        event_data: Dict[str, Any], 
        partition_key: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Send an event to the specified topic.
        Uses partition_key (e.g. organization_id) to ensure ordering within tenant.
        """
        if not self.producer:
            logger.error("Producer is not started.")
            return False
            
        # Inject trace IDs if not present
        if "correlation_id" not in event_data:
            event_data["correlation_id"] = correlation_id or str(uuid.uuid4())
            
        try:
            await self.producer.send_and_wait(
                topic.value,
                value=event_data,
                key=partition_key
            )
            return True
        except Exception as e:
            logger.error(f"Failed to produce message to topic {topic.value}: {e}")
            # In a real scenario, we might want to fallback to a local disk buffer or DB log
            return False
