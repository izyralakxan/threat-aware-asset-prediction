"""
Maps a CVE to the MITRE ATT&CK tactic and technique an attacker would most
likely use it for, from its weakness type (CWE), CVSS vector and
description.

This is an ESTIMATE in the spirit of MITRE Engenuity's "Mapping ATT&CK to
CVE for Impact" methodology (vulnerability type -> exploitation technique
-> tactic). The project has no official per-CVE ATT&CK data, so every
mapping is labelled as estimated where it is shown.

Each rule also gives a short interim mitigation for when the patch cannot
be applied yet.
"""

import re

# (name, CWE ids, description keywords) checked in order: the first match wins
RULES = [
    ("rce", {"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-502", "CWE-434", "CWE-917", "CWE-1336"},
     r"execute arbitrary (code|commands)|remote code execution|code execution|command injection|"
     r"arbitrary code"),
    ("privilege_escalation", {"CWE-269", "CWE-250", "CWE-266", "CWE-274", "CWE-648"},
     r"elevation of privilege|escalat\w* (of )?privileges?|gain (elevated|root|system|administrator)|"
     r"privilege escalation"),
    ("auth_bypass", {"CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-306", "CWE-862", "CWE-863",
                     "CWE-639", "CWE-284", "CWE-285"},
     r"authentication bypass|bypass (the )?authentication|without authentication|unauthori[sz]ed access"),
    ("credential_access", {"CWE-522", "CWE-256", "CWE-798", "CWE-312", "CWE-319", "CWE-521", "CWE-916"},
     r"credential|password|session token|hard-?coded"),
    ("sql_injection", {"CWE-89", "CWE-943"}, r"sql injection"),
    ("xss", {"CWE-79", "CWE-80"}, r"cross[- ]site scripting|\bxss\b"),
    ("csrf", {"CWE-352"}, r"cross[- ]site request forgery|\bcsrf\b"),
    ("feature_bypass", {"CWE-693", "CWE-358", "CWE-1021"}, r"security feature bypass|bypass .*protection"),
    ("info_disclosure", {"CWE-200", "CWE-209", "CWE-532", "CWE-22", "CWE-23", "CWE-36", "CWE-918",
                         "CWE-552", "CWE-538", "CWE-1188"},
     r"information disclosure|disclose|read arbitrary files|arbitrary file read|file read|"
     r"path traversal|directory traversal|"
     r"server-side request forgery|ssrf|sensitive information"),
    ("dos", {"CWE-400", "CWE-770", "CWE-835", "CWE-674", "CWE-476", "CWE-401", "CWE-404", "CWE-834"},
     r"denial of service|denial-of-service|\bcrash|resource exhaustion|infinite loop"),
    ("memory_corruption", {"CWE-787", "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-416",
                           "CWE-415", "CWE-190", "CWE-843", "CWE-824"},
     r"buffer overflow|out-of-bounds|use[- ]after[- ]free|heap|memory corruption|type confusion"),
]

# What each kind of flaw gives an attacker: (tactic, technique, interim mitigation)
MAPPING = {
    "rce_remote": ("Initial Access", "T1190 Exploit Public-Facing Application",
                   "Block or restrict access to the affected service from untrusted networks "
                   "(firewall, VPN-only access or WAF rule) until patched."),
    "rce_user": ("Execution", "T1203 Exploitation for Client Execution",
                 "Warn users not to open untrusted files or links; block risky file types at the "
                 "email and web gateways."),
    "rce_local": ("Execution", "T1203 Exploitation for Client Execution",
                  "Limit who can log on to the device and run software on it."),
    "privilege_escalation": ("Privilege Escalation", "T1068 Exploitation for Privilege Escalation",
                             "Remove unneeded local admin rights and alert on new administrator "
                             "accounts or services."),
    "auth_bypass": ("Initial Access", "T1190 Exploit Public-Facing Application",
                    "Restrict the login or management interface to trusted IP addresses and "
                    "review recent sign-ins."),
    "credential_access": ("Credential Access", "T1212 Exploitation for Credential Access",
                          "Rotate passwords, keys and tokens used by this system and enforce MFA."),
    "sql_injection": ("Initial Access", "T1190 Exploit Public-Facing Application",
                      "Add a WAF rule for SQL injection and give the application database account "
                      "least privilege."),
    "xss": ("Initial Access", "T1189 Drive-by Compromise",
            "Enable a strict Content Security Policy and warn users about suspicious links."),
    "csrf": ("Initial Access", "T1189 Drive-by Compromise",
             "Require re-authentication for sensitive actions and warn users about suspicious links."),
    "feature_bypass": ("Defense Evasion", "T1211 Exploitation for Defense Evasion",
                       "Add detection rules for the bypassed control and monitor for misuse."),
    "info_disclosure": ("Collection", "T1005 Data from Local System",
                        "Restrict access to the service and review logs for unusual file or data "
                        "access."),
    "dos": ("Impact", "T1499 Endpoint Denial of Service",
            "Rate-limit or filter traffic to the service and monitor its availability."),
    "memory_corruption_remote": ("Initial Access", "T1190 Exploit Public-Facing Application",
                                 "Block or restrict access to the affected service from untrusted "
                                 "networks until patched."),
    "memory_corruption_local": ("Execution", "T1203 Exploitation for Client Execution",
                                "Warn users not to open untrusted files or links; keep exploit "
                                "protection (EDR) enabled."),
    "default_remote": ("Initial Access", "T1190 Exploit Public-Facing Application",
                       "Restrict network access to the affected service until patched."),
    "default_local": ("Execution", "T1203 Exploitation for Client Execution",
                      "Limit who can use the device and keep endpoint protection enabled."),
}


def cwe_set(value):
    return set(re.findall(r"CWE-\d+", str(value or "")))


def classify(cwe, description, attack_vector, user_interaction):
    """Kind of flaw, from CWE first, then description keywords."""
    cwes = cwe_set(cwe)
    text = str(description or "").lower()
    kind = next((name for name, ids, _ in RULES if cwes & ids), None) \
        or next((name for name, _, pattern in RULES if re.search(pattern, text)), None)

    remote = str(attack_vector).upper() in {"NETWORK", "ADJACENT_NETWORK", "ADJACENT"}
    needs_user = str(user_interaction).upper() in {"REQUIRED", "PASSIVE", "ACTIVE"}

    if kind == "rce":
        return "rce_user" if needs_user else ("rce_remote" if remote else "rce_local")
    if kind == "memory_corruption":
        return "memory_corruption_remote" if remote and not needs_user else "memory_corruption_local"
    if kind is None:
        return "default_remote" if remote and not needs_user else "default_local"
    return kind


def map_cve(cwe, description, attack_vector, user_interaction):
    """(tactic, technique, interim mitigation) for one CVE."""
    return MAPPING[classify(cwe, description, attack_vector, user_interaction)]
