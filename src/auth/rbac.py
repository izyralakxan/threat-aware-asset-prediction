"""
Role-based access control: roles, permissions and visible tabs.

Least privilege and separation of duties:
  - the Administrator manages accounts but does not send remediation
    notices or accept risk
  - only the Security Manager accepts risk
  - Asset Owners see only their own team's assets
  - the Auditor reads everything, including the audit log, but changes nothing
"""

ROLES = {
    "admin": "Administrator",
    "security_manager": "Security Manager",
    "analyst": "Security Analyst",
    "asset_owner": "Asset Owner",
    "auditor": "Auditor",
}

PERMISSIONS = {
    "view_all_assets":    {"admin", "security_manager", "analyst", "auditor"},
    "view_attack_paths":  {"admin", "security_manager", "analyst", "auditor"},
    "view_model":         {"admin", "security_manager", "analyst", "auditor"},
    "upload_scans":       {"admin", "analyst"},
    "reload_data":        {"admin", "security_manager", "analyst"},
    "assign_owners":      {"admin", "security_manager", "analyst"},
    "send_notifications": {"security_manager", "analyst"},
    "view_notifications": {"security_manager", "analyst", "auditor"},
    "update_task_status": {"security_manager", "analyst", "asset_owner"},
    "accept_risk":        {"security_manager"},
    "manage_users":       {"admin"},
    "view_audit":         {"admin", "security_manager", "auditor"},
    "export":             {"admin", "security_manager", "analyst", "asset_owner", "auditor"},
}

# Tab key -> permission needed (None = every signed-in user)
TAB_ACCESS = {
    "home": None, "overview": None, "detail": None, "remediation": None, "live": None,
    "compare": None,
    "paths": "view_attack_paths", "model": "view_model", "backtest": "view_model",
    "notifications": "view_notifications",
    "admin": "view_audit",
}


# Used only while sign-in is switched off in config/auth.json (development)
DEVELOPER_ROLE = "developer"


def can(user, permission):
    if user is not None and user["role"] == DEVELOPER_ROLE:
        return True
    return user is not None and user["role"] in PERMISSIONS.get(permission, set())


def role_name(role):
    return "Developer (full access)" if role == DEVELOPER_ROLE else ROLES.get(role, role)
