from sqlalchemy import Column, String, Boolean
from sqlalchemy.orm import relationship
from app.db.base_class import Base, UUIDModel, TimestampModel, SoftDeleteModel

class Organization(Base, UUIDModel, TimestampModel, SoftDeleteModel):
    __tablename__ = "organizations"
    
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=True, unique=True, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="organization", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="organization", cascade="all, delete-orphan")
