from fastapi import APIRouter
from app.schemas.health import HealthStatus, ReadinessStatus
from app.core.config import settings

router = APIRouter()

@router.get("", response_model=HealthStatus)
def health_check():
    """General health check."""
    return HealthStatus(
        status="ok",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT
    )

@router.get("/live", response_model=HealthStatus)
def liveness_check():
    """Liveness probe."""
    return HealthStatus(
        status="ok",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT
    )

@router.get("/ready", response_model=ReadinessStatus)
def readiness_check():
    """Readiness probe. Checks dependencies in Phase 2+."""
    # TODO: Implement actual checks for PostgreSQL, Redis, Elasticsearch, Kafka in later phases
    return ReadinessStatus(
        status="ok",
        database="unknown",
        cache="unknown",
        message="Dependency checks not yet implemented"
    )
