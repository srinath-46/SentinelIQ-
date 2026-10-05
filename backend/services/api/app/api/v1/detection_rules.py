from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List
from uuid import UUID

from app.db.session import get_db
from app.models.detection_rule import DetectionRule
from app.schemas.detection_rule import DetectionRuleCreate, DetectionRuleRead, DetectionRuleUpdate
from app.api.dependencies import get_current_user

router = APIRouter()

@router.get("/", response_model=List[DetectionRuleRead])
async def list_detection_rules(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    organization_id = current_user.get("organization_id")
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.organization_id == organization_id)
    )
    return result.scalars().all()

@router.post("/", response_model=DetectionRuleRead, status_code=status.HTTP_201_CREATED)
async def create_detection_rule(
    rule_in: DetectionRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    organization_id = current_user.get("organization_id")
    user_id = current_user.get("user_id")
    
    db_rule = DetectionRule(
        **rule_in.model_dump(),
        organization_id=organization_id,
        created_by=user_id,
        updated_by=user_id,
        version=1,
        lifecycle_state="ACTIVE"
    )
    db.add(db_rule)
    await db.commit()
    await db.refresh(db_rule)
    return db_rule

@router.get("/{rule_id}", response_model=DetectionRuleRead)
async def get_detection_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    organization_id = current_user.get("organization_id")
    
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id == rule_id,
            DetectionRule.organization_id == organization_id
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection Rule not found")
    return rule
