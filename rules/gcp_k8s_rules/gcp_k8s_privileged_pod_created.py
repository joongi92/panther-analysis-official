from panther_base_helpers import deep_get
from panther_gcp_helpers import gcp_alert_context


def rule(event):
    if event.deep_get("protoPayload", "response", "status") == "Failure":
        return False

    if event.deep_get("protoPayload", "methodName") != "io.k8s.core.v1.pods.create":
        return False

    authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
    if not authorization_info:
        return False
    containers_info = event.deep_walk("protoPayload", "response", "spec", "containers")
    for auth in authorization_info:
        if auth.get("permission") == "io.k8s.core.v1.pods.create" and auth.get("granted") is True:
            for security_context in containers_info:
                if (
                    deep_get(security_context, "securityContext", "privileged") is True
                    or deep_get(security_context, "securityContext", "runAsNonRoot") is False
                ):
                    return True

    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    pod_name = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] created a privileged pod [{pod_name}] in project [{project_id}]"


def dedup(event):
    return event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )


def alert_context(event):
    context = gcp_alert_context(event)
    containers_info = event.deep_walk("protoPayload", "response", "spec", "containers", default=[])
    context["pod_security_context"] = [i.get("securityContext") for i in containers_info]
    return context
