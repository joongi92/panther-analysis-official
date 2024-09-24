""" This Python code is used for multiple scheduled rules.
"""

import ipaddress


def rule(event):
    # Ignore IPv6
    ip_address = event.get("m_ip_address")
    try:
        if ipaddress.ip_address(ip_address).version != 4:
            return False
    except ValueError:
        return False

    return True


def alert_context(event):
    return {"ip_address": event.get("m_ip_address"), "username": event.get("m_username")}
