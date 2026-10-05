from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional
from uuid import UUID

from app.api.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.incident import Incident
from app.schemas.incidents import IncidentResponse
from app.services.elasticsearch import ElasticsearchService

router = APIRouter()
es_service = ElasticsearchService()

@router.get("/", response_model=List[IncidentResponse])
async def list_incidents(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    status: Optional[str] = None,
    limit: int = Query(50, le=100),
    offset: int = 0
):
    query = select(Incident).where(Incident.organization_id == current_user.organization_id)
    if status:
        query = query.where(Incident.status == status.upper())
    
    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = await db.get(Incident, incident_id)
    if not incident or incident.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("/{incident_id}/acknowledge", response_model=IncidentResponse)
async def acknowledge_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = await db.get(Incident, incident_id)
    if not incident or incident.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    setattr(incident, "status", "ACKNOWLEDGED")
    incident.assignee_id = current_user.id
    
    await db.commit()
    await db.refresh(incident)
    return incident

@router.post("/{incident_id}/resolve", response_model=IncidentResponse)
async def resolve_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = await db.get(Incident, incident_id)
    if not incident or incident.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    setattr(incident, "status", "RESOLVED")
    
    await db.commit()
    await db.refresh(incident)
    return incident

@router.get("/{incident_id}/timeline")
async def incident_timeline(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = await db.get(Incident, incident_id)
    if not incident or incident.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    from datetime import datetime, timezone
    events = await es_service.search_events(
        organization_id=str(current_user.organization_id),
        start_time=datetime.min.replace(tzinfo=timezone.utc),
        end_time=datetime.max.replace(tzinfo=timezone.utc),
        filters={"metadata.incident_id": str(incident_id)},
        limit=100
    )
    return {"incident": incident_id, "timeline": [hit["_source"] for hit in events.get("hits", {}).get("hits", [])]}
