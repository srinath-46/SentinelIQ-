from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, BigInteger
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime, timezone
from app.db.base_class import Base, UUIDModel

class SecurityEvent(Base, UUIDModel):
    __tablename__ = "security_events"

    # Core Identifiers
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Timestamps
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Source info
    source = Column(String(50), nullable=False, index=True)
    source_event_id = Column(String(255), nullable=True)
    event_type = Column(String(50), nullable=False, index=True)

    # Relationships
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)

    # Network fields
    source_ip = Column(String(45), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    destination_port = Column(Integer, nullable=True)
    destination_domain = Column(String(255), nullable=True, index=True)
    destination_url = Column(String, nullable=True)
    protocol = Column(String(50), nullable=True)

    # Context
    action = Column(String(50), nullable=True)
    resource = Column(String, nullable=True)
    resource_type = Column(String(100), nullable=True)
    severity = Column(String(50), nullable=True, index=True)

    # Metrics
    bytes_in = Column(BigInteger, nullable=True)
    bytes_out = Column(BigInteger, nullable=True)

    # Process Info
    process_name = Column(String(255), nullable=True)
    process_id = Column(BigInteger, nullable=True)
    parent_process_id = Column(BigInteger, nullable=True)

    # Identity / Application
    application = Column(String(255), nullable=True)
    authentication_method = Column(String(100), nullable=True)

    # Location
    location = Column(JSONB, nullable=True)

    # Classification
    data_classification = Column(String(50), nullable=True)
    sensitivity = Column(String(50), nullable=True)

    # Extensibility
    metadata_ = Column("metadata", JSONB, nullable=True)
    raw_event_reference = Column(String, nullable=True)
    raw_event = Column(JSONB, nullable=True)

    # ORM relationships
    organization = relationship("Organization")
    user = relationship("User")
    device = relationship("Device")
