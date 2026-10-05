from typing import Dict, Any, Optional
from datetime import datetime, timezone
from uuid import UUID
import logging

from app.schemas.events import SecurityEventIngest
from app.core.event_types import EventSource, EventType, EventAction, EventSeverity

logger = logging.getLogger(__name__)

class WazuhParser:
    """Parses raw Wazuh alerts into normalized SentinelIQ security events."""
    
    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        try:
            # Wazuh typically sends ISO8601, e.g. 2023-10-12T15:23:10.123+0000
            # A fallback parser for robust handling
            from dateutil.parser import parse
            return parse(ts_str)
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _map_severity(level: int) -> EventSeverity:
        if level <= 4:
            return EventSeverity.low
        elif level <= 7:
            return EventSeverity.medium
        elif level <= 10:
            return EventSeverity.high
        else:
            return EventSeverity.critical

    @staticmethod
    def _determine_event_type_and_action(alert: Dict[str, Any]) -> tuple[EventType, Optional[EventAction]]:
        groups = alert.get("rule", {}).get("groups", [])
        
        # File Integrity Monitoring
        if "syscheck" in alert:
            syscheck = alert["syscheck"]
            event_action = syscheck.get("event")
            if event_action == "added":
                return EventType.file_create, EventAction.create
            elif event_action == "modified":
                return EventType.file_modify, EventAction.modify
            elif event_action == "deleted":
                return EventType.file_delete, EventAction.delete
            return EventType.file_access, EventAction.access
            
        # Authentication
        if "authentication_success" in groups:
            return EventType.login, EventAction.authenticate
        if "authentication_failed" in groups:
            return EventType.authentication_failure, EventAction.deny
            
        # Process monitoring
        if "process_start" in groups or "ossec" in groups:
            # Simple heuristic, refine based on actual rule IDs or fields
            if alert.get("data", {}).get("command") or alert.get("data", {}).get("process"):
                return EventType.process_start, EventAction.execute
                
        # Default
        return EventType.security_alert, None

    def parse(self, raw_alert: Dict[str, Any], tenant_id: Optional[UUID] = None) -> Optional[SecurityEventIngest]:
        """Parse a single Wazuh alert dictionary into a normalized event."""
        try:
            timestamp_str = raw_alert.get("timestamp")
            if not timestamp_str:
                logger.warning("Wazuh alert missing timestamp. Skipping.")
                return None
                
            timestamp = self._parse_timestamp(timestamp_str)
            
            rule = raw_alert.get("rule", {})
            agent = raw_alert.get("agent", {})
            data = raw_alert.get("data", {})
            
            event_type, action = self._determine_event_type_and_action(raw_alert)
            severity = self._map_severity(rule.get("level", 0))
            
            # Construct metadata
            metadata = {
                "wazuh_rule_id": rule.get("id"),
                "wazuh_rule_description": rule.get("description"),
                "wazuh_agent_id": agent.get("id"),
                "wazuh_agent_name": agent.get("name")
            }
            if "mitre" in rule:
                metadata["mitre"] = rule["mitre"]

            # Resource extraction
            resource = None
            resource_type = None
            if "syscheck" in raw_alert:
                resource = raw_alert["syscheck"].get("path")
                resource_type = "file"
            elif "dstuser" in data:
                resource = data["dstuser"]
                resource_type = "user"
                
            process_name = data.get("process") or data.get("command")
            
            # Network fields from data if present
            srcip = data.get("srcip")
            srcport = data.get("srcport")
            dstip = data.get("dstip")
            dstport = data.get("dstport")
            
            try:
                srcport_int = int(srcport) if srcport else None
            except ValueError:
                srcport_int = None
                
            try:
                dstport_int = int(dstport) if dstport else None
            except ValueError:
                dstport_int = None

            event = SecurityEventIngest(
                timestamp=timestamp,
                source=EventSource.wazuh,
                source_event_id=raw_alert.get("id"),
                event_type=event_type,
                action=action,
                severity=severity,
                source_ip=srcip,
                source_port=srcport_int,
                destination_ip=dstip,
                destination_port=dstport_int,
                process_name=process_name,
                resource=resource,
                resource_type=resource_type,
                metadata=metadata,
                raw_event=raw_alert
            )
            return event
        except Exception as e:
            logger.error(f"Error parsing Wazuh alert: {e}", exc_info=True)
            return None
