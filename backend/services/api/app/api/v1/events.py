from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Optional
from uuid import UUID
from datetime import datetime
import logging

from app.db.session import get_db
from app.api.dependencies import get_current_active_user
from app.core.permissions import RequirePermission, Permission
from app.schemas.events import SecurityEventIngest, SecurityEventRead
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.models.device import Device
from app.core.event_types import EventSource, EventType, EventSeverity

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED)
async def create_event(
    event_in: SecurityEventIngest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequirePermission(Permission.EVENTS_CREATE))
):
    """Ingest a new normalized security event."""
    # 1. Tenant assignment
    organization_id = current_user.organization_id
    
    # 2. Validate user_id ownership if provided
    if event_in.user_id:
        # Avoid full query, just check existence in tenant
        user_exists = await db.scalar(
            select(1).where(User.id == event_in.user_id, User.organization_id == organization_id)
        )
        if not user_exists:
            raise HTTPException(status_code=400, detail="Invalid user_id for organization")

    # 3. Validate device_id ownership if provided
    if event_in.device_id:
        device_exists = await db.scalar(
            select(1).where(Device.id == event_in.device_id, Device.organization_id == organization_id)
        )
        if not device_exists:
            raise HTTPException(status_code=400, detail="Invalid device_id for organization")

    # 4. Construct DB model
    # Note: Event schemas use metadata as alias for metadata_
    event_data = event_in.model_dump(exclude_unset=True, by_alias=True)
    if "metadata" in event_data:
        event_data["metadata_"] = event_data.pop("metadata")
        
    db_event = SecurityEvent(
        organization_id=organization_id, # type: ignore
        **event_data
    )
    
    db.add(db_event)
    try:
        await db.commit()
        await db.refresh(db_event)
        
        logger.info(
            f"Security event created", 
            extra={
                "event_id": str(db_event.id),
                "organization_id": str(organization_id),
                "source": db_event.source,
                "event_type": db_event.event_type
            }
        )
        return db_event
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to create event: {e}")
        raise HTTPException(status_code=500, detail="Internal database error")


@router.get("", response_model=List[SecurityEventRead])
async def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    event_type: Optional[EventType] = None,
    source: Optional[EventSource] = None,
    severity: Optional[EventSeverity] = None,
    user_id: Optional[UUID] = None,
    device_id: Optional[UUID] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequirePermission(Permission.EVENTS_READ))
):
    """Retrieve security events for the authenticated organization."""
    query = select(SecurityEvent).where(SecurityEvent.organization_id == current_user.organization_id)

    # Apply filters
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    if source:
        query = query.where(SecurityEvent.source == source)
    if severity:
        query = query.where(SecurityEvent.severity == severity)
    if user_id:
        query = query.where(SecurityEvent.user_id == user_id)
    if device_id:
        query = query.where(SecurityEvent.device_id == device_id)
    if start_time:
        query = query.where(SecurityEvent.timestamp >= start_time)
    if end_time:
        query = query.where(SecurityEvent.timestamp <= end_time)

    # Ordering and Pagination
    query = query.order_by(desc(SecurityEvent.timestamp))
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    events = result.scalars().all()
    return events


@router.get("/{event_id}", response_model=SecurityEventRead)
async def get_event(
    event_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequirePermission(Permission.EVENTS_READ))
):
    """Retrieve a single security event."""
    query = select(SecurityEvent).where(
        SecurityEvent.id == event_id,
        SecurityEvent.organization_id == current_user.organization_id
    )
    result = await db.execute(query)
    event = result.scalar_one_or_none()
    
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
        
    return event
