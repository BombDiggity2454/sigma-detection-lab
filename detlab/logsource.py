"""Map Sigma ``logsource`` blocks to concrete event channels and event IDs.

Every event fed to the engine must carry a ``Channel`` field (exactly as it
appears in Windows Event Viewer / the EVTX ``System.Channel`` element). That
lets a rule for ``category: process_access`` match only Sysmon EID 10 events,
instead of any event that happens to have a ``TargetImage`` field.

Note: ``process_creation`` maps to Sysmon EID 1 only. Security 4688 uses
different field names (``NewProcessName`` rather than ``Image``) and would
need a field-mapping layer, which is on the roadmap.
"""

from __future__ import annotations

from typing import Any, Mapping

SYSMON = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"

# category -> list of (channel, allowed EventIDs or None for "any")
CATEGORY_MAP: dict[str, list[tuple[str, set[int] | None]]] = {
    "process_creation": [(SYSMON, {1})],
    "network_connection": [(SYSMON, {3})],
    "image_load": [(SYSMON, {7})],
    "process_access": [(SYSMON, {10})],
    "file_event": [(SYSMON, {11})],
    "registry_add": [(SYSMON, {12})],
    "registry_delete": [(SYSMON, {12})],
    "registry_set": [(SYSMON, {13})],
    "registry_event": [(SYSMON, {12, 13, 14})],
    "dns_query": [(SYSMON, {22})],
    "ps_script": [(POWERSHELL, {4104})],
    "webserver": [("webserver", None)],
}

SERVICE_MAP: dict[str, str] = {
    "security": "Security",
    "system": "System",
    "sysmon": SYSMON,
    "powershell": POWERSHELL,
    "application": "Application",
}


class UnknownLogsource(ValueError):
    pass


def logsource_matches(logsource: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    channel = str(event.get("Channel", ""))
    category = logsource.get("category")
    service = logsource.get("service")

    if category:
        if category not in CATEGORY_MAP:
            raise UnknownLogsource(f"no channel mapping for category {category!r}")
        for chan, ids in CATEGORY_MAP[category]:
            if channel.lower() == chan.lower():
                if ids is None:
                    return True
                try:
                    return int(event.get("EventID", -1)) in ids
                except (TypeError, ValueError):
                    return False
        return False

    if service:
        if service not in SERVICE_MAP:
            raise UnknownLogsource(f"no channel mapping for service {service!r}")
        return channel.lower() == SERVICE_MAP[service].lower()

    raise UnknownLogsource("logsource needs a category or service")
