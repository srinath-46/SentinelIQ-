import pytest
from datetime import datetime
from collectors.wazuh.parser import WazuhParser
from app.core.event_types import EventSource, EventType, EventAction, EventSeverity

@pytest.fixture
def parser():
    return WazuhParser()

def test_parse_auth_failed(parser):
    raw_alert = {
        "timestamp": "2023-10-12T15:23:10.123+0000",
        "rule": {
            "level": 5,
            "description": "sshd: authentication failed.",
            "id": "5716",
            "groups": ["syslog", "sshd", "authentication_failed"]
        },
        "id": "1697124190.12345",
        "data": {
            "srcip": "10.0.0.5",
            "srcport": "45678",
            "dstuser": "root"
        }
    }
    
    event = parser.parse(raw_alert)
    assert event is not None
    assert event.source == EventSource.wazuh
    assert event.source_event_id == "1697124190.12345"
    assert event.event_type == EventType.authentication_failure
    assert event.action == EventAction.deny
    assert event.severity == EventSeverity.medium
    assert event.source_ip == "10.0.0.5"
    assert event.source_port == 45678
    assert event.resource == "root"
    assert event.resource_type == "user"

def test_parse_syscheck_modified(parser):
    raw_alert = {
        "timestamp": "2023-10-12T16:00:00.000+0000",
        "rule": {
            "level": 8,
            "description": "Integrity checksum changed.",
            "id": "550",
            "groups": ["ossec", "syscheck"]
        },
        "id": "1697124191.99999",
        "syscheck": {
            "path": "/etc/shadow",
            "event": "modified"
        }
    }
    
    event = parser.parse(raw_alert)
    assert event is not None
    assert event.event_type == EventType.file_modify
    assert event.action == EventAction.modify
    assert event.severity == EventSeverity.high
    assert event.resource == "/etc/shadow"
    assert event.resource_type == "file"

def test_parse_missing_timestamp(parser):
    raw_alert = {
        "rule": {"level": 3, "groups": ["authentication_success"]}
    }
    event = parser.parse(raw_alert)
    assert event is None  # Should fail gracefully

def test_parse_malformed_port(parser):
    raw_alert = {
        "timestamp": "2023-10-12T15:23:10.123+0000",
        "data": {
            "srcport": "not-a-number"
        }
    }
    event = parser.parse(raw_alert)
    assert event is not None
    assert event.source_port is None  # Handled gracefully
