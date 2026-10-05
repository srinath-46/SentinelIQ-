import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import as_declarative, declared_attr
from sqlalchemy import Column, DateTime
from sqlalchemy.dialects.postgresql import UUID

@as_declarative()
class Base:
    id: Any
    __name__: str

    # Explicit __tablename__ is provided by child models

class UUIDModel:
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

class TimestampModel:
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

class SoftDeleteModel:
    deleted_at = Column(DateTime(timezone=True), nullable=True)
