from abc import ABC, abstractmethod
from typing import List, AsyncGenerator, TypeVar, Generic
from pydantic import BaseModel

from app.schemas.events import SecurityEventIngest

class CloudCollectorConfig(BaseModel):
    """Base configuration for cloud collectors."""
    enabled: bool = False
    organization_id: str
    
T_Config = TypeVar('T_Config', bound=CloudCollectorConfig)

class CloudAdapter(ABC, Generic[T_Config]):
    """
    Abstract Base Class for Cloud Telemetry Adapters.
    Enforces a strict contract for fetching and normalizing cloud events.
    """
    
    def __init__(self, config: T_Config):
        self.config = config

    @abstractmethod
    async def validate_configuration(self) -> bool:
        """
        Validate that the provided credentials and configuration are sufficient
        to connect to the cloud provider. Must not fake connections.
        """
        pass

    @abstractmethod
    async def fetch_events(self) -> AsyncGenerator[SecurityEventIngest, None]:
        """
        Fetch new security events from the cloud provider, normalize them to
        SecurityEventIngest, and yield them.
        """
        if False:
            yield None # type: ignore
