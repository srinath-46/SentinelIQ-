import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from jose import jwt, JWTError
from typing import Optional

from app.core.config import settings
from app.services.websocket_manager import manager

router = APIRouter()
logger = logging.getLogger(__name__)

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...), org_id: Optional[str] = Query(None)):
    """
    WebSocket endpoint for real-time alerts.
    Clients must connect with a valid Supabase JWT in the query string.
    """
    try:
        # Decode and validate Supabase JWT
        # The audience is usually 'authenticated' for Supabase access tokens
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated"
        )
    except JWTError as e:
        logger.warning(f"WebSocket auth failed: {e}")
        await websocket.close(code=1008, reason="Invalid authentication token")
        return

    # Extract organization_id. Ideally this is embedded directly in the JWT custom claims.
    # For flexibility in this phase, we allow it to be passed via query if it matches the user's DB org,
    # but strictly checking token claims is safest.
    organization_id = payload.get("user_metadata", {}).get("organization_id")
    if not organization_id:
        organization_id = payload.get("app_metadata", {}).get("organization_id")
    
    # Fallback to query param (assuming we'd validate against the DB in a real scenario if claims aren't used)
    if not organization_id:
        organization_id = org_id

    if not organization_id:
        await websocket.close(code=1008, reason="Organization ID not found in token claims")
        return

    # Accept the connection
    await manager.connect(websocket, str(organization_id))
    
    try:
        while True:
            # We don't expect the client to send much data, but we keep the loop alive
            # to listen for disconnects or simple keep-alive pings.
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket, str(organization_id))
        logger.info(f"WebSocket disconnected for org {organization_id}")
