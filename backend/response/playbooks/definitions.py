from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class PlaybookCondition(BaseModel):
    field: str
    operator: str # "eq", "contains", "gt", "lt"
    value: Any

class PlaybookAction(BaseModel):
    action_name: str
    target_field: str # The field in the event to extract the target from (e.g., "source_ip")
    require_approval: bool = False

class Playbook(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool = True
    conditions: List[PlaybookCondition]
    actions: List[PlaybookAction]

# Default OOTB Playbooks
DEFAULT_PLAYBOOKS = [
    Playbook(
        id="pb-ransomware-isolate",
        name="Ransomware Isolation",
        description="Immediately isolate hosts showing signs of ransomware behavior.",
        enabled=True,
        conditions=[
            PlaybookCondition(field="metadata.predicted_threat_class", operator="eq", value="ransomware_behavior"),
            PlaybookCondition(field="severity", operator="eq", value="critical")
        ],
        actions=[
            PlaybookAction(action_name="isolate_host", target_field="device_id", require_approval=False)
        ]
    ),
    Playbook(
        id="pb-brute-force-block",
        name="Brute Force IP Block",
        description="Block IPs performing credential stuffing.",
        enabled=True,
        conditions=[
            PlaybookCondition(field="metadata.predicted_threat_class", operator="eq", value="credential_stuffing")
        ],
        actions=[
            PlaybookAction(action_name="block_ip", target_field="source_ip", require_approval=False),
            PlaybookAction(action_name="disable_user", target_field="user_id", require_approval=True)
        ]
    )
]
