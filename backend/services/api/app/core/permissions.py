from enum import Enum
from typing import List, Dict
from fastapi import HTTPException, status, Depends
from app.models.user import User

class Role(str, Enum):
    ADMIN = "Admin"
    SOC_ANALYST = "SOC Analyst"
    SECURITY_MANAGER = "Security Manager"
    AUDITOR = "Auditor"

class Permission(str, Enum):
    EVENTS_READ = "events.read"
    EVENTS_CREATE = "events.create"
    ALERTS_READ = "alerts.read"
    ALERTS_UPDATE = "alerts.update"
    INCIDENTS_READ = "incidents.read"
    INCIDENTS_INVESTIGATE = "incidents.investigate"
    INCIDENTS_CLOSE = "incidents.close"
    RISK_READ = "risk.read"
    USERS_READ = "users.read"
    USERS_MANAGE = "users.manage"
    DEVICES_READ = "devices.read"
    POLICIES_READ = "policies.read"
    POLICIES_MANAGE = "policies.manage"
    RESPONSE_EXECUTE = "response.execute"
    THREATS_READ = "threats.read"
    THREATS_MANAGE = "threats.manage"
    AUDIT_READ = "audit.read"
    REPORTS_READ = "reports.read"

ROLE_PERMISSIONS: Dict[Role, List[Permission]] = {
    Role.ADMIN: [p for p in Permission],
    Role.SOC_ANALYST: [
        Permission.EVENTS_READ, Permission.ALERTS_READ, Permission.ALERTS_UPDATE,
        Permission.INCIDENTS_READ, Permission.INCIDENTS_INVESTIGATE, Permission.INCIDENTS_CLOSE,
        Permission.RISK_READ, Permission.DEVICES_READ, Permission.THREATS_READ,
        Permission.RESPONSE_EXECUTE
    ],
    Role.SECURITY_MANAGER: [
        Permission.EVENTS_READ, Permission.ALERTS_READ, Permission.INCIDENTS_READ,
        Permission.RISK_READ, Permission.USERS_READ, Permission.DEVICES_READ,
        Permission.POLICIES_READ, Permission.POLICIES_MANAGE, Permission.THREATS_READ,
        Permission.THREATS_MANAGE, Permission.REPORTS_READ
    ],
    Role.AUDITOR: [
        Permission.EVENTS_READ, Permission.ALERTS_READ, Permission.INCIDENTS_READ,
        Permission.RISK_READ, Permission.USERS_READ, Permission.DEVICES_READ,
        Permission.POLICIES_READ, Permission.THREATS_READ, Permission.AUDIT_READ,
        Permission.REPORTS_READ
    ]
}

from app.api.dependencies import get_current_active_user

def has_permission(user_role: str, required_permission: Permission) -> bool:
    try:
        role_enum = Role(user_role)
        return required_permission in ROLE_PERMISSIONS.get(role_enum, [])
    except ValueError:
        return False

class RequirePermission:
    def __init__(self, required_permission: Permission):
        self.required_permission = required_permission

    def __call__(self, current_user: User = Depends(get_current_active_user)) -> User:
        if not has_permission(str(current_user.role), self.required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Requires {self.required_permission.value} permission."
            )
        return current_user
