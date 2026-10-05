from sqlalchemy import Column, String, Boolean, ForeignKey, Integer, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.db.base_class import Base, UUIDModel, TimestampModel

class DetectionRule(Base, UUIDModel, TimestampModel):
    __tablename__ = "detection_rules"
    
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    
    name = Column(String(255), nullable=False)
    description = Column(String, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    severity = Column(String(50), nullable=False)
    
    category = Column(String(100), nullable=True)
    subcategory = Column(String(100), nullable=True)
    
    conditions = Column(JSONB, nullable=False)
    threshold = Column(JSONB, nullable=True)
    correlation = Column(JSONB, nullable=True)
    sequence = Column(JSONB, nullable=True)
    
    required_event_types = Column(ARRAY(String), nullable=True)
    mitre_attack_techniques = Column(ARRAY(String), nullable=True)
    tags = Column(ARRAY(String), nullable=True)
    
    suppression = Column(JSONB, nullable=True)
    deduplication = Column(JSONB, nullable=True)
    
    source = Column(String(50), nullable=False, default="CUSTOM")
    lifecycle_state = Column(String(50), nullable=False, default="ACTIVE")
    version = Column(Integer, nullable=False, default=1)
    
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    organization = relationship("Organization")
    creator = relationship("User", foreign_keys=[created_by])
    updater = relationship("User", foreign_keys=[updated_by])
