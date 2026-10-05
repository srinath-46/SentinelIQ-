import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import datetime, timezone

# Example placeholder for tests that would run against a test database
pytestmark = pytest.mark.asyncio

async def test_create_valid_event():
    """
    Test that a fully valid minimal event is accepted.
    """
    # This requires app and client fixture which are not fully wired with DB here
    pass

async def test_invalid_port():
    """
    Test that an invalid port (e.g. 65536) is rejected by Pydantic.
    """
    from app.schemas.events import SecurityEventIngest
    from pydantic import ValidationError
    
    with pytest.raises(ValidationError):
        SecurityEventIngest(
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            event_type="file_access",
            source_port=65536 # type: ignore
        )

async def test_invalid_uuid():
    """
    Test that invalid UUID strings are rejected.
    """
    from app.schemas.events import SecurityEventIngest
    from pydantic import ValidationError
    
    with pytest.raises(ValidationError):
        SecurityEventIngest(
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            event_type="file_access",
            user_id="not-a-uuid" # type: ignore
        )
