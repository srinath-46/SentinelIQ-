import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from dateutil.parser import parse as parse_date

from app.schemas.events import SecurityEventIngest
from app.core.event_types import EventSource, EventType, EventAction, EventSeverity

logger = logging.getLogger(__name__)

class SuricataParser:
    """Parses raw Suricata EVE JSON logs into normalized SentinelIQ security events."""
    
    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        try:
            # Suricata sends ISO8601 with microseconds: 2023-10-12T15:23:10.123456+0000
            return parse_date(ts_str)
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _map_severity(severity: int) -> EventSeverity:
        # Suricata severities usually range 1-4, where 1 is highest priority.
        if severity == 1:
            return EventSeverity.high
        elif severity == 2:
            return EventSeverity.medium
        else:
            return EventSeverity.low

    def parse(self, raw_log: Dict[str, Any]) -> Optional[SecurityEventIngest]:
        """Parse a single Suricata EVE JSON dictionary."""
        try:
            ts_str = raw_log.get("timestamp")
            if not ts_str:
                logger.warning("Suricata log missing timestamp. Skipping.")
                return None
                
            timestamp = self._parse_timestamp(ts_str)
            eve_type = raw_log.get("event_type")
            flow_id = raw_log.get("flow_id")
            source_event_id = str(flow_id) if flow_id else None
            
            srcip = raw_log.get("src_ip")
            srcport = raw_log.get("src_port")
            dstip = raw_log.get("dest_ip")
            dstport = raw_log.get("dest_port")
            protocol = raw_log.get("proto")
            
            metadata = {
                "suricata_event_type": eve_type,
            }
            if flow_id:
                metadata["flow_id"] = flow_id
                
            event_type = EventType.network_connection
            action = EventAction.access
            severity = EventSeverity.low
            domain = None
            url = None
            resource = None
            resource_type = None

            # Handle Alerts
            if eve_type == "alert":
                event_type = EventType.security_alert
                alert_data = raw_log.get("alert", {})
                
                # Action mapped from alert action if present
                alert_action = alert_data.get("action")
                if alert_action == "allowed":
                    action = EventAction.allow
                elif alert_action in ["blocked", "dropped", "rejected"]:
                    action = EventAction.deny
                    
                severity = self._map_severity(alert_data.get("severity", 3))
                
                metadata["signature_id"] = alert_data.get("signature_id")
                metadata["signature"] = alert_data.get("signature")
                metadata["category"] = alert_data.get("category")
                
            # Handle Application Layer
            elif eve_type == "dns":
                event_type = EventType.dns_request
                action = EventAction.query
                dns_data = raw_log.get("dns", {})
                domain = dns_data.get("rrname")
                resource = domain
                resource_type = "domain"
                metadata["dns_type"] = dns_data.get("type")
                metadata["dns_rcode"] = dns_data.get("rcode")
                
            elif eve_type == "http":
                event_type = EventType.http_request
                http_data = raw_log.get("http", {})
                domain = http_data.get("hostname")
                url = http_data.get("url")
                resource = url
                resource_type = "url"
                metadata["http_method"] = http_data.get("http_method")
                metadata["status"] = http_data.get("status")
                
            elif eve_type == "tls":
                tls_data = raw_log.get("tls", {})
                domain = tls_data.get("sni")
                metadata["tls_version"] = tls_data.get("version")
                metadata["tls_subject"] = tls_data.get("subject")
                metadata["tls_issuerdn"] = tls_data.get("issuerdn")
                
            elif eve_type == "fileinfo":
                event_type = EventType.file_access
                action = EventAction.transfer
                file_data = raw_log.get("fileinfo", {})
                resource = file_data.get("filename")
                resource_type = "file"
                metadata["magic"] = file_data.get("magic")
                metadata["md5"] = file_data.get("md5")
                metadata["sha256"] = file_data.get("sha256")

            # Flow bytes if available
            bytes_in = None
            bytes_out = None
            if "flow" in raw_log:
                # Suricata tracks to_server / to_client
                # Normalizing to bytes_out (from client to server) and bytes_in (server to client)
                bytes_out = raw_log["flow"].get("bytes_toserver")
                bytes_in = raw_log["flow"].get("bytes_toclient")

            return SecurityEventIngest(
                timestamp=timestamp,
                source=EventSource.suricata,
                source_event_id=source_event_id,
                event_type=event_type,
                action=action,
                severity=severity,
                source_ip=srcip,
                source_port=srcport if isinstance(srcport, int) else None,
                destination_ip=dstip,
                destination_port=dstport if isinstance(dstport, int) else None,
                destination_domain=domain,
                destination_url=url,
                protocol=protocol,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
                resource=resource,
                resource_type=resource_type,
                metadata=metadata,
                raw_event=raw_log
            )
        except Exception as e:
            logger.error(f"Error parsing Suricata log: {e}", exc_info=True)
            return None
