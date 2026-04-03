import json
import time
import os
from pathlib import Path

# Define log file path relative to this file
OUTPUT_DIR = Path(__file__).parent / "dashboard"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = OUTPUT_DIR / "security_events.jsonl"
SCREENSHOTS_DIR = OUTPUT_DIR / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


class SecurityLogger:
    @staticmethod
    def log_event(
        event_type: str,
        url: str,
        details: str,
        risk_level: str,
        action: str,
        screenshot_path: str = None,
        risk_score: int = 0,
        explanation: str = None,
    ):
        """
        Logs a structured security event for the dashboard.

        Args:
            event_type: "INJECTION_ATTEMPT", "REPUTATION_WARNING", "ACTION_BLOCKED", etc.
            url: The URL where it happened
            details: Description of what was found
            risk_level: "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"
            action: "BLOCKED", "SANITIZED", "WARNED", "ALLOWED", "MONITOR", "EXPLAINED"
            screenshot_path: Optional path to a screenshot image
            risk_score: 0-100 score indicating threat severity
            explanation: Optional LLM-generated human-readable explanation
        """
        entry = {
            "timestamp": time.time(),
            "time_str": time.strftime("%H:%M:%S"),
            "event_type": event_type,
            "url": url,
            "details": details,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "action": action,
            "screenshot": screenshot_path,
            "explanation": explanation,
        }

        lock_file = LOG_FILE.with_name(LOG_FILE.name + ".lock")
        while True:
            try:
                fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                break
            except OSError:
                time.sleep(0.05)

        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"Failed to write security log: {e}")
        finally:
            try:
                os.unlink(str(lock_file))
            except OSError:
                pass

    @staticmethod
    def get_screenshot_dir():
        return SCREENSHOTS_DIR

    @staticmethod
    def clear_logs():
        if LOG_FILE.exists():
            os.remove(LOG_FILE)
