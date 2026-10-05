from sqlalchemy import Column, String, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.db.base_class import Base, UUIDModel, TimestampModel, SoftDeleteModel

class Incident(Base, UUIDModel, TimestampModel, SoftDeleteModel):
    __tablename__ = "incidents"
    
    title = Column(String(255), nullable=False)
    description = Column(String, nullable=True)
    status = Column(String(50), default="OPEN", nullable=False)
    severity = Column(String(50), default="MEDIUM", nullable=False)
    risk_score = Column(Integer, nullable=True)
    
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    assignee_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    organization = relationship("Organization", back_populates="incidents")
    assignee = relationship("User")
