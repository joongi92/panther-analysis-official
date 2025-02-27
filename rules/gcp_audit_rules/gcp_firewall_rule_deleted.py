import re

from panther_gcp_helpers import gcp_alert_context


def rule(event):
    method_pattern = r"(?:\w+\.)*v\d\.(?:Firewall\.Delete)|(compute\.firewalls\.delete)"
    match = re.search(method_pattern, event.deep_get("protoPayload", "methodName", default=""))
    return match is not None


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = event.deep_get(
        "protoPayload",
        "resourceName",
        default="<RESOURCE_NOT_FOUND>",
    )
    resource_id = event.deep_get(
        "resource",
        "labels",
        "firewall_rule_id",
        default="<RESOURCE_ID_NOT_FOUND>",
    )
    if resource_id != "<RESOURCE_ID_NOT_FOUND>":
        return f"[GCP]: [{actor}] deleted firewall rule with resource ID [{resource_id}]"
    return f"[GCP]: [{actor}] deleted firewall rule for resource [{resource}]"


def alert_context(event):
    return gcp_alert_context(event)
