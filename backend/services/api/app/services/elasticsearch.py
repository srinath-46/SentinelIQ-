import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

from app.core.config import settings

logger = logging.getLogger(__name__)

class ElasticsearchService:
    """Service for interacting with Elasticsearch for high-volume security events."""
    
    def __init__(self, es_url: Optional[str] = None):
        self.es_url = es_url or settings.ELASTICSEARCH_URL
        self.client = AsyncElasticsearch([self.es_url])
        
    async def close(self):
        await self.client.close()
        
    def _get_index_name(self, organization_id: str, dt: Optional[datetime] = None) -> str:
        """Generate index name based on tenant and date."""
        if not dt:
            dt = datetime.now(timezone.utc)
        date_str = dt.strftime("%Y.%m.%d")
        return f"sentineliq-events-{organization_id}-{date_str}"
        
    async def index_event(self, organization_id: str, event_data: Dict[str, Any]) -> bool:
        """Index a single event."""
        try:
            timestamp = event_data.get("timestamp") or datetime.now(timezone.utc)
            index = self._get_index_name(organization_id, timestamp if isinstance(timestamp, datetime) else None)
            
            # Map for ES
            if "timestamp" in event_data:
                event_data["@timestamp"] = event_data.pop("timestamp")
                
            await self.client.index(index=index, document=event_data)
            return True
        except Exception as e:
            logger.error(f"Failed to index event in ES: {e}")
            return False
            
    async def bulk_index_events(self, organization_id: str, events: List[Dict[str, Any]]) -> bool:
        """Bulk index multiple events."""
        def generate_actions():
            for event in events:
                timestamp = event.get("timestamp") or datetime.now(timezone.utc)
                idx = self._get_index_name(organization_id, timestamp if isinstance(timestamp, datetime) else None)
                
                doc = event.copy()
                if "timestamp" in doc:
                    doc["@timestamp"] = doc.pop("timestamp")
                    
                yield {
                    "_op_type": "index",
                    "_index": idx,
                    "_source": doc
                }
                
        try:
            await async_bulk(self.client, generate_actions())
            return True
        except Exception as e:
            logger.error(f"Failed bulk indexing to ES: {e}")
            return False

    async def search_events(
        self, 
        organization_id: str, 
        start_time: datetime, 
        end_time: datetime,
        query_string: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """Time-range search with strict tenant isolation."""
        # Use wildcard index matching but restricted to the tenant
        index_pattern = f"sentineliq-events-{organization_id}-*"
        
        # Build strict tenant and time range bool query
        must_queries = [
            {"term": {"organization_id": organization_id}},
            {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if query_string:
            # Simple query string to prevent arbitrary complex ES injection
            must_queries.append({
                "simple_query_string": {
                    "query": query_string,
                    "default_operator": "and"
                }
            })
            
        if filters:
            for k, v in filters.items():
                must_queries.append({"term": {k: v}})
                
        query = {
            "query": {
                "bool": {
                    "must": must_queries
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "from": offset,
            "size": limit
        }
        
        try:
            response = await self.client.search(index=index_pattern, body=query)
            return response # type: ignore
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return {"hits": {"total": {"value": 0}, "hits": []}}

    async def get_user_timeline(self, organization_id: str, user_id: str, limit: int = 100) -> List[Dict]:
        """Fetch timeline of events for a specific user."""
        res = await self.search_events(
            organization_id=organization_id,
            start_time=datetime.min,
            end_time=datetime.max,
            filters={"user_id": user_id},
            limit=limit
        )
        return [hit["_source"] for hit in res.get("hits", {}).get("hits", [])]

    async def get_device_timeline(self, organization_id: str, device_id: str, limit: int = 100) -> List[Dict]:
        """Fetch timeline of events for a specific device."""
        res = await self.search_events(
            organization_id=organization_id,
            start_time=datetime.min,
            end_time=datetime.max,
            filters={"device_id": device_id},
            limit=limit
        )
        return [hit["_source"] for hit in res.get("hits", {}).get("hits", [])]
