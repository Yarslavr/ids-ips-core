import re
from typing import Dict, Any, Tuple, Optional


class SignatureEngine:
    def __init__(self, rules_data: list[Dict[str, Any]]):

        self.rules = []
        for r in rules_data:
            compiled_rule = {
                "id": r["id"],
                "rev": r.get("rev", 1),
                "name": r["name"],
                "action": r.get("action", "alert"),
                "severity": r.get("severity", "LOW"),
                "mitre": r.get("mitre_technique", "N/A"),
                "protocol": r.get("protocol", "any").lower(),
                "dst_port": r.get("dst_port"),
                "regex": re.compile(r["pattern"]),
                "description": r["description"]
            }
            self.rules.append(compiled_rule)

    def check(self, payload: str, protocol: str = "tcp", dst_port: Optional[int] = None) -> Tuple[bool, str, Dict[str, Any]]:
        if not payload:
            return False, "accept", {}

        proto_lower = protocol.lower()

        for rule in self.rules:
            if rule["protocol"] != "any" and rule["protocol"] != proto_lower:
                continue

            if rule["dst_port"] is not None and dst_port is not None:
                if rule["dst_port"] != dst_port:
                    continue

            if rule["regex"].search(payload):
                alert_info = {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "mitre": rule["mitre"],
                    "action": rule["action"],
                    "description": rule["description"]
                }
                return True, rule["action"], alert_info

        return False, "accept", {}