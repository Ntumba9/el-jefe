"""Simulated containment actions.

None of these call any real identity provider, firewall, or session store.
Each one only returns a description of what *would* happen, and that
description — never a real side effect — is what gets written to the
audit trail. This is the structural enforcement of "never execute
containment actions without explicit administrator approval": approval
alone still only ever reaches this simulation layer.
"""

SUPPORTED_ACTIONS = {
    "revoke_sessions",
    "disable_account",
    "block_ip",
    "request_password_reset",
}


def simulate(action: str, username: str, source_ip: str, approved: bool) -> str:
    if not approved:
        return f"No action taken: administrator disapproved the response for '{username}'."
    if action not in SUPPORTED_ACTIONS:
        return f"No action taken: '{action}' is not a recognized response action."

    descriptions = {
        "revoke_sessions": f"[SIMULATED] All active sessions for '{username}' would be revoked.",
        "disable_account": f"[SIMULATED] Account '{username}' would be disabled.",
        "block_ip": f"[SIMULATED] Source IP {source_ip} would be blocked at the edge.",
        "request_password_reset": f"[SIMULATED] A forced password reset would be requested for '{username}'.",
    }
    return descriptions[action]
