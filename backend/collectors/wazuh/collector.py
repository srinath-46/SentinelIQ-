import httpx
import logging
import asyncio
from typing import List, Optional
from uuid import UUID

from collectors.wazuh.parser import WazuhParser
from app.schemas.events import SecurityEventIngest
from app.core.config import settings

logger = logging.getLogger(__name__)

class WazuhCollector:
    """Connects to Wazuh API, fetches alerts, and yields parsed events."""
    
    def __init__(self, api_url: Optional[str] = None, user: Optional[str] = None, password: Optional[str] = None):
        self.api_url = api_url or settings.WAZUH_API_URL
        self.user = user or settings.WAZUH_USER
        self.password = password or settings.WAZUH_PASSWORD
        self.parser = WazuhParser()
        self.token = None
        self._client = httpx.AsyncClient(verify=False) # In prod, configure correct CA
        
    async def authenticate(self) -> bool:
        if not self.api_url or not self.user or not self.password:
            logger.error("Wazuh credentials not configured.")
            return False
            
        try:
            # Wazuh API auth uses Basic auth to get a JWT
            response = await self._client.post(
                f"{self.api_url}/security/user/authenticate",
                auth=(self.user, self.password),
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()
            self.token = data.get("data", {}).get("token")
            return bool(self.token)
        except Exception as e:
            logger.error(f"Failed to authenticate with Wazuh API: {e}")
            return False

    async def fetch_recent_alerts(self, limit: int = 100) -> List[SecurityEventIngest]:
        """Fetch the most recent alerts from Wazuh and parse them."""
        if not self.token:
            if not await self.authenticate():
                return []
                
        headers = {"Authorization": f"Bearer {self.token}"}
        
        try:
            # Querying Wazuh alerts index /security/alerts or /alerts
            # Wazuh 4.x typical endpoint for alerts (requires Wazuh Indexer access or specific API endpoints)
            # We'll use a standard API endpoint assuming security analytics is available
            response = await self._client.get(
                f"{self.api_url}/security/alerts",
                headers=headers,
                params={"limit": limit, "sort": "-timestamp"},
                timeout=15.0
            )
            
            if response.status_code == 401:
                # Token expired, retry auth
                await self.authenticate()
                headers["Authorization"] = f"Bearer {self.token}"
                response = await self._client.get(
                    f"{self.api_url}/security/alerts",
                    headers=headers,
                    params={"limit": limit, "sort": "-timestamp"},
                    timeout=15.0
                )
                
            response.raise_for_status()
            data = response.json()
            
            alerts = data.get("data", {}).get("items", [])
            parsed_events = []
            
            for alert in alerts:
                event = self.parser.parse(alert)
                if event:
                    parsed_events.append(event)
                    
            return parsed_events
        except Exception as e:
            logger.error(f"Failed to fetch Wazuh alerts: {e}")
            return []

    async def close(self):
        await self._client.aclose()
