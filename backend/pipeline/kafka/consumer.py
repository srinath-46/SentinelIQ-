import json
import logging
import asyncio
import inspect
from typing import Callable, Any, Dict, List, Optional
from aiokafka import AIOKafkaConsumer

from app.core.config import settings
from pipeline.kafka.topics import KafkaTopic
from pipeline.kafka.producer import EventProducer

logger = logging.getLogger(__name__)

class EventConsumer:
    """Async Kafka Consumer with Dead-Letter support."""
    
    def __init__(
        self, 
        topics: List[KafkaTopic], 
        group_id: str,
        dlq_producer: EventProducer,
        bootstrap_servers: Optional[str] = None
    ):
        self.bootstrap_servers = bootstrap_servers or settings.KAFKA_BOOTSTRAP_SERVERS
        self.topic_names = [t.value for t in topics]
        self.group_id = group_id
        self.consumer = None
        self.dlq_producer = dlq_producer
        self._running = False
        
    async def start(self):
        self.consumer = AIOKafkaConsumer(
            *self.topic_names,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')) if m else None,
            key_deserializer=lambda m: m.decode('utf-8') if m else None,
            auto_offset_reset="earliest",
            enable_auto_commit=False  # Manual commit for exactly-once-like guarantees
        )
        await self.consumer.start()
        self._running = True
        logger.info(f"Kafka Consumer started for groups {self.group_id} on topics {self.topic_names}")

    async def stop(self):
        self._running = False
        if self.consumer:
            await self.consumer.stop()
            logger.info("Kafka Consumer stopped")

    async def consume(self, handler: Callable[[Dict[str, Any]], Any]):
        """
        Consume messages indefinitely, passing them to the handler.
        If handler raises an exception, send to DLQ and commit offset.
        """
        if not self.consumer:
            logger.error("Consumer not started.")
            return

        try:
            async for msg in self.consumer:
                if not self._running:
                    break
                    
                event_data = msg.value
                try:
                    # Await handler if async, otherwise call sync
                    if inspect.iscoroutinefunction(handler):
                        await handler(event_data)
                    else:
                        handler(event_data)
                    
                    # Commit successful processing
                    await self.consumer.commit()
                except Exception as e:
                    logger.error(f"Error processing message {msg.topic}:{msg.partition}:{msg.offset} - {e}")
                    
                    # Dead-Letter Strategy
                    dlq_message = {
                        "original_topic": msg.topic,
                        "original_partition": msg.partition,
                        "original_offset": msg.offset,
                        "error": str(e),
                        "payload": event_data
                    }
                    dlq_success = await self.dlq_producer.send_event(
                        topic=KafkaTopic.DEAD_LETTER,
                        event_data=dlq_message,
                        partition_key=msg.key
                    )
                    
                    if dlq_success:
                        # Safely committed to DLQ, move past the poison pill
                        await self.consumer.commit()
                    else:
                        logger.critical("Failed to write to DLQ. Halting consumption to prevent data loss.")
                        self._running = False
                        break
        except Exception as e:
            logger.error(f"Consumer error: {e}")
