from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.db.base_class import Base, UUIDModel, TimestampModel, SoftDeleteModel

class Device(Base, UUIDModel, TimestampModel, SoftDeleteModel):
    __tablename__ = "devices"
    
    hostname = Column(String(255), index=True, nullable=False)
    ip_address = Column(String(45), nullable=True)
    mac_address = Column(String(17), nullable=True)
    os_info = Column(String(255), nullable=True)
    agent_id = Column(String(255), unique=True, index=True, nullable=False) # E.g., Wazuh agent ID
    
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    
    organization = relationship("Organization", back_populates="devices")
