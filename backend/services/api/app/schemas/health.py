from pydantic import BaseModel

class HealthStatus(BaseModel):
    status: str
    version: str
    environment: str

class ReadinessStatus(BaseModel):
    status: str
    database: str
    cache: str
    message: str
