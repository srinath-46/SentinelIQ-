from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
from uuid import UUID

class IncidentBase(BaseModel):
    title: str = Field(..., max_length=255)
    description: Optional[str] = None
    status: str = Field(default="OPEN")
    severity: str = Field(default="MEDIUM")
    risk_score: Optional[int] = None
    assignee_id: Optional[UUID] = None

class IncidentCreate(IncidentBase):
    pass

class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[int] = None
    assignee_id: Optional[UUID] = None

class IncidentResponse(IncidentBase):
    id: UUID
    organization_id: UUID
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
