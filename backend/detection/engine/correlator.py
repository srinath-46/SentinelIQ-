import json
import logging
from typing import Dict, Any, Optional
import redis.asyncio as redis
from uuid import UUID

logger = logging.getLogger(__name__)

class CorrelationEngine:
    """Handles temporal correlation, thresholding, and deduplication for Detection Rules."""
    
    def __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url)

    async def check_suppression(self, rule: Any, event: Dict[str, Any]) -> bool:
        """Returns True if the detection should be suppressed."""
        if getattr(rule, "suppression", None):
            suppression = rule.suppression
            duration = suppression.get("duration_seconds", 3600)
            group_by = suppression.get("group_by", [])
            
            key_parts = [f"suppress:{rule.id}"]
            for field in group_by:
                val = event.get(field, "unknown")
                key_parts.append(f"{field}:{val}")
                
            key = ":".join(key_parts)
            
            # If key exists, it's suppressed
            if await self.redis.exists(key):
                return True
                
            # Otherwise set it to suppress future events
            await self.redis.set(key, "1", ex=duration)
            return False
            
        return False

    async def check_threshold(self, rule: Any, event: Dict[str, Any]) -> bool:
        """
        Returns True if the threshold has been MET. 
        If there's no threshold config, it returns True immediately.
        """
        if not getattr(rule, "threshold", None):
            return True
            
        threshold = rule.threshold
        count = threshold.get("count", 1)
        time_window = threshold.get("time_window_seconds", 60)
        group_by = threshold.get("group_by", [])
        
        key_parts = [f"threshold:{rule.id}"]
        for field in group_by:
            val = event.get(field, "unknown")
            key_parts.append(f"{field}:{val}")
            
        key = ":".join(key_parts)
        
        # Increment the counter
        current_count = await self.redis.incr(key)
        
        # If it's the first hit, set the expiry window
        if current_count == 1:
            await self.redis.expire(key, time_window)
            
        if current_count >= count:
            # We reached the threshold! Reset counter so we don't alert repeatedly
            # unless suppression handles that.
            await self.redis.delete(key)
            return True
            
        return False

    async def check_deduplication(self, rule: Any, event: Dict[str, Any]) -> bool:
        """Returns True if this is a duplicate event that should be ignored."""
        if getattr(rule, "deduplication", None):
            dedup = rule.deduplication
            time_window = dedup.get("time_window_seconds", 300)
            fields = dedup.get("fields", [])
            
            if not fields:
                return False
                
            key_parts = [f"dedup:{rule.id}"]
            for field in fields:
                val = event.get(field, "unknown")
                key_parts.append(f"{field}:{val}")
                
            key = ":".join(key_parts)
            
            if await self.redis.exists(key):
                return True
                
            await self.redis.set(key, "1", ex=time_window)
            
        return False

    async def process(self, rule: Any, event: Dict[str, Any]) -> bool:
        """
        Run all stateful correlation logic.
        Returns True if a Detection Finding should be generated.
        """
        # 1. Deduplication
        if await self.check_deduplication(rule, event):
            logger.debug(f"Event deduplicated for rule {rule.id}")
            return False
            
        # 2. Thresholding
        if not await self.check_threshold(rule, event):
            logger.debug(f"Threshold not met for rule {rule.id}")
            return False
            
        # 3. Suppression
        if await self.check_suppression(rule, event):
            logger.debug(f"Alert suppressed for rule {rule.id}")
            return False
            
        return True

    async def close(self):
        await self.redis.close()
