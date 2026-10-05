from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Optional, Any, Dict
from datetime import datetime
from uuid import UUID
from app.core.event_types import EventSource, EventType, EventAction, EventSeverity, DataClassification, Sensitivity

class LocationSchema(BaseModel):
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

class SecurityEventBase(BaseModel):
    timestamp: datetime
    source: EventSource
    source_event_id: Optional[str] = None
    event_type: EventType
    
    user_id: Optional[UUID] = None
    device_id: Optional[UUID] = None
    
    source_ip: Optional[str] = None
    source_port: Optional[int] = Field(None, ge=0, le=65535)
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = Field(None, ge=0, le=65535)
    destination_domain: Optional[str] = None
    destination_url: Optional[str] = None
    protocol: Optional[str] = None
    
    action: Optional[EventAction] = None
    resource: Optional[str] = None
    resource_type: Optional[str] = None
    severity: Optional[EventSeverity] = None
    
    bytes_in: Optional[int] = Field(None, ge=0)
    bytes_out: Optional[int] = Field(None, ge=0)
    
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_id: Optional[int] = None
    
    application: Optional[str] = None
    authentication_method: Optional[str] = None
    
    location: Optional[LocationSchema] = None
    
    data_classification: Optional[DataClassification] = None
    sensitivity: Optional[Sensitivity] = None
    
    metadata_: Optional[Dict[str, Any]] = Field(None, alias="metadata")
    raw_event_reference: Optional[str] = None
    raw_event: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(populate_by_name=True)

class SecurityEventIngest(SecurityEventBase):
    """Schema for incoming telemetry, without trusted server fields."""
    pass

class SecurityEventCreate(SecurityEventBase):
    """Internal creation schema, includes server-assigned tenant."""
    organization_id: UUID

class SecurityEventRead(SecurityEventBase):
    """Schema returned to clients."""
    id: UUID
    organization_id: UUID
    received_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
