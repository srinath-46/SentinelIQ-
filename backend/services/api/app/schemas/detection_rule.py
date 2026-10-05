from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

class DetectionRuleCondition(BaseModel):
    field: str
    operator: str
    value: Any

class DetectionRuleConditions(BaseModel):
    operator: str = "AND"
    conditions: List[Any]  # Can be DetectionRuleCondition or nested DetectionRuleConditions

class DetectionRuleBase(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    severity: str
    category: Optional[str] = None
    subcategory: Optional[str] = None
    
    conditions: Dict[str, Any]
    threshold: Optional[Dict[str, Any]] = None
    correlation: Optional[Dict[str, Any]] = None
    sequence: Optional[Dict[str, Any]] = None
    
    required_event_types: Optional[List[str]] = None
    mitre_attack_techniques: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    
    suppression: Optional[Dict[str, Any]] = None
    deduplication: Optional[Dict[str, Any]] = None

class DetectionRuleCreate(DetectionRuleBase):
    pass

class DetectionRuleUpdate(DetectionRuleBase):
    pass

class DetectionRuleRead(DetectionRuleBase):
    id: UUID
    organization_id: UUID
    source: str
    lifecycle_state: str
    version: int
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
