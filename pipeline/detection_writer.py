"""
Detection Writer: Generates Sigma and Suricata detection rules from sessions.
"""
import os
from typing import List, Dict, Any


class DetectionWriter:
    """Writes Sigma and Suricata rules from discovered threat patterns."""

    def write_sigma_rules(self, sessions: List[Dict[str, Any]],
                          output_dir: str = "analysis-pipeline/detections/sigma") -> List[str]:
        """Generate Sigma rules for detected threats."""
        os.makedirs(output_dir, exist_ok=True)
        files = []

        # Rule 1: Successful honeypot authentication (potential compromise)
        rule_content = """title: Honeypot Successful Authentication
id: ubi-soc-stage6-auth-success
status: experimental
description: Detects successful authentication on honeypot services
author: UBI SOC Stage 6 Pipeline
date: 2026-07-29
tags:
  - attack.initial_access
  - attack.t1110
logsource:
  product: honeypot
detection:
  selection:
    action: auth_success
  condition: selection
falsepositives:
  - Legitimate security testing
level: high
"""
        filepath = os.path.join(output_dir, "honeypot_auth_success.yml")
        with open(filepath, "w") as f:
            f.write(rule_content)
        files.append(filepath)

        # Rule 2: Command execution on honeypot
        rule_content = """title: Honeypot Command Execution
id: ubi-soc-stage6-command-exec
status: experimental
description: Detects command execution on honeypot services after successful auth
author: UBI SOC Stage 6 Pipeline
date: 2026-07-29
tags:
  - attack.execution
  - attack.t1059
logsource:
  product: honeypot
detection:
  selection:
    action: command
  condition: selection
falsepositives:
  - Legitimate security testing
level: critical
"""
        filepath = os.path.join(output_dir, "honeypot_command_exec.yml")
        with open(filepath, "w") as f:
            f.write(rule_content)
        files.append(filepath)

        # Rule 3: Payload download on honeypot
        rule_content = """title: Honeypot Payload Download
id: ubi-soc-stage6-payload-download
status: experimental
description: Detects malware payload download on honeypot services
author: UBI SOC Stage 6 Pipeline
date: 2026-07-29
tags:
  - attack.persistence
  - attack.t1105
logsource:
  product: honeypot
detection:
  selection:
    action: payload_download
  condition: selection
falsepositives:
  - None expected
level: critical
"""
        filepath = os.path.join(output_dir, "honeypot_payload_download.yml")
        with open(filepath, "w") as f:
            f.write(rule_content)
        files.append(filepath)

        return files

    def write_suricata_rules(self, sessions: List[Dict[str, Any]],
                            output_dir: str = "analysis-pipeline/detections") -> str:
        """Generate Suricata rules for detected threats."""
        os.makedirs(output_dir, exist_ok=True)
        rules = []

        # Generate rules for each full attack source IP
        attack_sessions = [s for s in sessions if s["session_type"] == "full_attack"]
        for session in attack_sessions:
            ip = session["source_ip"]
            proto = session["protocol"]
            port = {"ssh": 22, "telnet": 23, "http": 80, "mqtt": 1883}.get(proto, 0)

            if port:
                rules.append(
                    f'alert tcp {ip} any -> $HOME_NET {port} '
                    f'(msg:"UBI-SOC: Honeypot full attack from {ip} on {proto}"; '
                    f'flow:to_server,established; '
                    f'sid:100{hash(ip) % 100000:05d}; rev:1;)'
                )

        filepath = os.path.join(output_dir, "suricata.rules")
        with open(filepath, "w") as f:
            f.write("\n".join(rules) + "\n")
        return filepath

    def write_detections(self, sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Write all detection rules and return file paths."""
        sigma_files = self.write_sigma_rules(sessions)
        suricata_file = self.write_suricata_rules(sessions)

        return {
            "sigma_files": sigma_files,
            "suricata_file": suricata_file,
            "sigma_count": len(sigma_files),
            "suricata_count": len([s for s in sessions if s["session_type"] == "full_attack"]),
        }
