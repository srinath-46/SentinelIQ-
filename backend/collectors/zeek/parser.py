import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from app.schemas.events import SecurityEventIngest
from app.core.event_types import EventSource, EventType, EventAction, EventSeverity

logger = logging.getLogger(__name__)

class ZeekParser:
    """Parses raw Zeek JSON logs into normalized SentinelIQ security events."""
    
    @staticmethod
    def _parse_timestamp(ts: Any) -> datetime:
        try:
            # Zeek logs typically use unix epoch timestamps as floats
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    def parse(self, log_type: str, raw_log: Dict[str, Any]) -> Optional[SecurityEventIngest]:
        """
        Parse a single Zeek JSON log.
        log_type should be e.g. 'conn', 'dns', 'http', 'ssl', 'files'
        """
        try:
            ts_val = raw_log.get("ts")
            if ts_val is None:
                logger.warning("Zeek log missing timestamp. Skipping.")
                return None
                
            timestamp = self._parse_timestamp(ts_val)
            uid = raw_log.get("uid")
            
            # Network identity (Zeek uses id.orig_h, id.orig_p, etc.)
            # Some logs like 'files' might not have them at the root, but most connection logs do.
            srcip = raw_log.get("id.orig_h")
            srcport = raw_log.get("id.orig_p")
            dstip = raw_log.get("id.resp_h")
            dstport = raw_log.get("id.resp_p")
            
            protocol = raw_log.get("proto")
            
            bytes_in = raw_log.get("orig_bytes")
            bytes_out = raw_log.get("resp_bytes")
            
            metadata = {
                "zeek_log_type": log_type,
                "zeek_uid": uid
            }
            
            event_type = EventType.network_connection
            action = EventAction.connect
            severity = EventSeverity.low
            domain = None
            url = None
            resource = None
            resource_type = None

            # Enrich based on log type
            if log_type == "conn":
                metadata["conn_state"] = raw_log.get("conn_state")
                metadata["duration"] = raw_log.get("duration")
                metadata["service"] = raw_log.get("service")
                
            elif log_type == "dns":
                event_type = EventType.dns_request
                action = EventAction.query
                domain = raw_log.get("query")
                resource = domain
                resource_type = "domain"
                metadata["qtype_name"] = raw_log.get("qtype_name")
                metadata["rcode_name"] = raw_log.get("rcode_name")
                
            elif log_type == "http":
                event_type = EventType.http_request
                action = EventAction.access
                domain = raw_log.get("host")
                url = raw_log.get("uri")
                resource = url
                resource_type = "url"
                metadata["method"] = raw_log.get("method")
                metadata["status_code"] = raw_log.get("status_code")
                metadata["user_agent"] = raw_log.get("user_agent")
                
            elif log_type == "ssl" or log_type == "tls":
                domain = raw_log.get("server_name")
                metadata["version"] = raw_log.get("version")
                metadata["cipher"] = raw_log.get("cipher")
                
            elif log_type == "files":
                event_type = EventType.file_access
                action = EventAction.transfer
                resource = raw_log.get("filename")
                resource_type = "file"
                metadata["mime_type"] = raw_log.get("mime_type")
                metadata["md5"] = raw_log.get("md5")
                metadata["sha1"] = raw_log.get("sha1")

            return SecurityEventIngest(
                timestamp=timestamp,
                source=EventSource.zeek,
                source_event_id=uid,
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
                bytes_in=bytes_in if isinstance(bytes_in, int) else None,
                bytes_out=bytes_out if isinstance(bytes_out, int) else None,
                resource=resource,
                resource_type=resource_type,
                metadata=metadata,
                raw_event=raw_log
            )
        except Exception as e:
            logger.error(f"Error parsing Zeek log: {e}", exc_info=True)
            return None
