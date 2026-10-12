"""
Desktop Notification Dispatcher (macOS osascript / Linux notify-send).
"""
import subprocess
import platform

class DesktopNotifier:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.os_type = platform.system()

    def notify(self, title: str, message: str, severity: str = "HIGH"):
        if not self.enabled:
            return

        try:
            if self.os_type == "Darwin":
                # macOS Native Notification
                script = f'display notification "{message}" with title "🛡️ {title}" subtitle "MITM Sentinel [{severity}]"'
                subprocess.run(["osascript", "-e", script], capture_output=True, timeout=2.0)
            elif self.os_type == "Linux":
                # Linux notify-send
                urgency = "critical" if severity in ["CRITICAL", "HIGH"] else "normal"
                subprocess.run(["notify-send", "-u", urgency, title, message], capture_output=True, timeout=2.0)
        except Exception:
            pass
