from enum import Enum

class KafkaTopic(str, Enum):
    SECURITY_EVENTS = "security-events"
    ENDPOINT_EVENTS = "endpoint-events"
    NETWORK_EVENTS = "network-events"
    DATA_EVENTS = "data-events"
    ALERTS = "alerts"
    INCIDENTS = "incidents"
    DETECTIONS = "detections"
    ENRICHED_EVENTS = "enriched-events"
    DEAD_LETTER = "dead-letter"
