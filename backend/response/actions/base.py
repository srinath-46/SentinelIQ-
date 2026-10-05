from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel

class ActionConfig(BaseModel):
    enabled: bool = True
    require_approval: bool = False
    
class ResponseAction(ABC):
    """
    Abstract Base Class for all automated and manual Response Actions.
    """
    def __init__(self, config: ActionConfig):
        self.config = config

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the action (e.g., 'block_ip_palo_alto')."""
        pass

    @abstractmethod
    async def execute(self, target: str, context: Dict[str, Any]) -> bool:
        """
        Execute the action against the target.
        Must return True if successful, False otherwise.
        """
        pass
