import logging
from typing import Dict, List
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        # mapping of organization_id to a list of active websocket connections
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, organization_id: str):
        """Accept a websocket connection and register it to the organization."""
        await websocket.accept()
        if organization_id not in self.active_connections:
            self.active_connections[organization_id] = []
        self.active_connections[organization_id].append(websocket)
        logger.info(f"WebSocket connected for org {organization_id}. Total connections: {len(self.active_connections[organization_id])}")

    def disconnect(self, websocket: WebSocket, organization_id: str):
        """Remove a websocket connection from the registry."""
        if organization_id in self.active_connections:
            if websocket in self.active_connections[organization_id]:
                self.active_connections[organization_id].remove(websocket)
                if not self.active_connections[organization_id]:
                    del self.active_connections[organization_id]

    async def broadcast_to_org(self, organization_id: str, message: dict):
        """Send a JSON message to all active websockets in a specific organization."""
        if organization_id in self.active_connections:
            dead_connections = []
            for connection in self.active_connections[organization_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"WebSocket send failed: {e}")
                    dead_connections.append(connection)
            
            # Cleanup dead connections
            for dead in dead_connections:
                self.disconnect(dead, organization_id)

manager = ConnectionManager()
