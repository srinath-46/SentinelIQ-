from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logging import setup_logging
from app.core.middleware import RequestContextMiddleware
from app.core.exceptions import global_exception_handler
from app.api.v1.health import router as health_router
from app.api.v1.events import router as events_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.websockets import router as websockets_router
from app.api.v1.detection_rules import router as detection_rules_router
import logging
from contextlib import asynccontextmanager

# Setup Logging
setup_logging(settings.ENVIRONMENT)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SentinelIQ API...")
    yield
    logger.info("Shutting down SentinelIQ API...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Middleware
app.add_middleware(RequestContextMiddleware)

# Exception Handlers
app.add_exception_handler(Exception, global_exception_handler)

# Routers
app.include_router(health_router, prefix=f"{settings.API_V1_STR}/health", tags=["health"])
app.include_router(events_router, prefix=f"{settings.API_V1_STR}/events", tags=["events"])
app.include_router(incidents_router, prefix=f"{settings.API_V1_STR}/incidents", tags=["incidents"])
app.include_router(websockets_router, prefix=f"{settings.API_V1_STR}/notifications", tags=["websockets"])
app.include_router(detection_rules_router, prefix=f"{settings.API_V1_STR}/detection-rules", tags=["detection-rules"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
