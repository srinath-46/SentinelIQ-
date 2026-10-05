import pytest
from datetime import datetime, timezone
from collectors.suricata.parser import SuricataParser
from app.core.event_types import EventSource, EventType, EventAction, EventSeverity

@pytest.fixture
def parser():
    return SuricataParser()

def test_parse_alert(parser):
    raw_log = {
        "timestamp": "2023-10-12T15:23:10.123456+0000",
        "flow_id": 123456789012345,
        "event_type": "alert",
        "src_ip": "192.168.1.10",
        "src_port": 45678,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2013028,
            "signature": "ET POLICY Suspicious",
            "category": "Potentially Bad Traffic",
            "severity": 2
        }
    }
    
    event = parser.parse(raw_log)
    assert event is not None
    assert event.source == EventSource.suricata
    assert event.source_event_id == "123456789012345"
    assert event.event_type == EventType.security_alert
    assert event.action == EventAction.allow
    assert event.severity == EventSeverity.medium
    assert event.source_ip == "192.168.1.10"
    assert event.source_port == 45678
    assert event.destination_ip == "10.0.0.5"
    assert event.destination_port == 80
    assert event.protocol == "TCP"
    assert event.metadata["signature_id"] == 2013028
    assert event.metadata["signature"] == "ET POLICY Suspicious"
    
def test_parse_dns(parser):
    raw_log = {
        "timestamp": "2023-10-12T15:23:10.123456+0000",
        "event_type": "dns",
        "src_ip": "192.168.1.10",
        "src_port": 5353,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "id": 12345,
            "rrname": "example.com"
        }
    }
    
    event = parser.parse(raw_log)
    assert event is not None
    assert event.event_type == EventType.dns_request
    assert event.action == EventAction.query
    assert event.destination_domain == "example.com"
    assert event.resource == "example.com"
    assert event.resource_type == "domain"

def test_parse_http_with_flow(parser):
    raw_log = {
        "timestamp": "2023-10-12T15:23:10.123456+0000",
        "event_type": "http",
        "http": {
            "hostname": "example.com",
            "url": "/upload",
            "http_method": "POST",
            "status": 200
        },
        "flow": {
            "bytes_toserver": 1500,
            "bytes_toclient": 300
        }
    }
    
    event = parser.parse(raw_log)
    assert event is not None
    assert event.event_type == EventType.http_request
    assert event.destination_domain == "example.com"
    assert event.destination_url == "/upload"
    assert event.bytes_out == 1500
    assert event.bytes_in == 300
