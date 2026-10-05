import pytest
from datetime import datetime, timezone
from collectors.zeek.parser import ZeekParser
from app.core.event_types import EventSource, EventType, EventAction, EventSeverity

@pytest.fixture
def parser():
    return ZeekParser()

def test_parse_conn_log(parser):
    raw_log = {
        "ts": 1697124190.12345,
        "uid": "CHhAvVGS1DHFgh123",
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 45678,
        "id.resp_h": "10.0.0.5",
        "id.resp_p": 80,
        "proto": "tcp",
        "service": "http",
        "duration": 0.123,
        "orig_bytes": 450,
        "resp_bytes": 3210,
        "conn_state": "SF"
    }
    
    event = parser.parse("conn", raw_log)
    assert event is not None
    assert event.source == EventSource.zeek
    assert event.source_event_id == "CHhAvVGS1DHFgh123"
    assert event.event_type == EventType.network_connection
    assert event.action == EventAction.connect
    assert event.source_ip == "192.168.1.10"
    assert event.source_port == 45678
    assert event.destination_ip == "10.0.0.5"
    assert event.destination_port == 80
    assert event.protocol == "tcp"
    assert event.bytes_in == 450
    assert event.bytes_out == 3210
    
    # Check timestamp conversion (should be UTC)
    expected_ts = datetime.fromtimestamp(1697124190.12345, tz=timezone.utc)
    assert event.timestamp == expected_ts

def test_parse_dns_log(parser):
    raw_log = {
        "ts": 1697124190.12345,
        "uid": "Cabc12345",
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 5353,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "proto": "udp",
        "query": "example.com",
        "qtype_name": "A"
    }
    
    event = parser.parse("dns", raw_log)
    assert event is not None
    assert event.event_type == EventType.dns_request
    assert event.action == EventAction.query
    assert event.destination_domain == "example.com"
    assert event.resource == "example.com"
    assert event.resource_type == "domain"
    assert event.metadata["qtype_name"] == "A"

def test_parse_http_log(parser):
    raw_log = {
        "ts": 1697124190.12345,
        "uid": "Chttp123",
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 45678,
        "id.resp_h": "10.0.0.5",
        "id.resp_p": 80,
        "method": "GET",
        "host": "example.com",
        "uri": "/upload",
        "status_code": 200
    }
    
    event = parser.parse("http", raw_log)
    assert event is not None
    assert event.event_type == EventType.http_request
    assert event.action == EventAction.access
    assert event.destination_domain == "example.com"
    assert event.destination_url == "/upload"
    assert event.metadata["status_code"] == 200
    
def test_parse_missing_ts(parser):
    raw_log = {"uid": "123"}
    event = parser.parse("conn", raw_log)
    assert event is None
