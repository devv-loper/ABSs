import json
from pathlib import Path
from typing import Dict, List
import re
import urllib.parse
from security.event_logger import SecurityLogger

class PolicyEngine:
    """
    Enterprise Role-Based Access Control (RBAC) & Policy Enforcement for AI Agents.
    Allows admins to set hard constraints on what the agent can and cannot do.
    """
    def __init__(self, config_dir: Path):
        self.config_file = config_dir / "policies.json"
        self.logger = SecurityLogger()
        self.reload_policies()

    def reload_policies(self):
        """Loads or creates the default enterprise policy file."""
        if not self.config_file.parent.exists():
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    self.policies = json.load(f)
            except Exception:
                self.policies = self._default_policies()
        else:
            self.policies = self._default_policies()
            self.save_policies()
            
    def save_policies(self):
        with open(self.config_file, "w") as f:
            json.dump(self.policies, f, indent=4)

    def _default_policies(self) -> Dict:
        return {
            "block_domains": ["*.ru", "*.cn", "bit.ly", "tinyurl.com", "pastebin.com"],
            "block_input_patterns": ["password", "ssn", "credit_card", "secret_key"],
            "max_risk_tolerance": 75,
            "require_human_approval": False,
            "blocked_actions": []
        }
        
    def check_navigation(self, url: str) -> bool:
        """Returns True if blocked, False if allowed."""
        self.reload_policies()
        try:
            domain = urllib.parse.urlparse(url).netloc.lower()
            for blocked in self.policies.get("block_domains", []):
                # Wildcard matching
                pattern = blocked.replace(".", "\.").replace("*", ".*")
                if re.search(f"^{pattern}$", domain):
                    self.logger.log_event(
                        event_type="POLICY_VIOLATION",
                        risk_level="CRITICAL",
                        risk_score=95,
                        action="BLOCKED",
                        details=f"[OWASP LLM07 | MITRE AML.T0042] Navigation to {domain} blocked by Enterprise Policy.",
                        url=url
                    )
                    return True
        except Exception:
            pass
        return False
        
    def check_input(self, text: str) -> bool:
        """Returns True if the text contains a blocked pattern (regex or keyword)."""
        self.reload_policies()
        text_lower = str(text).lower()
        for pattern in self.policies.get("block_input_patterns", []):
            if pattern.lower() in text_lower:
                self.logger.log_event(
                    event_type="POLICY_VIOLATION",
                    risk_level="HIGH",
                    risk_score=85,
                    action="BLOCKED",
                    details=f"[OWASP LLM07 | MITRE AML.T0042] Agent attempted to input sensitive data matching policy: '{pattern}'.",
                    url="N/A"
                )
                return True
        return False

    def check_action(self, action_type: str) -> bool:
        """Returns True if the action is in the blocked list."""
        self.reload_policies()
        blocked = self.policies.get("blocked_actions", [])
        if blocked and action_type in blocked:
            self.logger.log_event(
                event_type="POLICY_VIOLATION",
                risk_level="HIGH",
                risk_score=80,
                action="BLOCKED",
                details=f"[OWASP LLM07 | MITRE AML.T0042] Action '{action_type}' is found in the blocked actions policy.",
                url="N/A"
            )
            return True
        return False
