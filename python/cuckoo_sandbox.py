import requests
import time
from typing import Dict, Optional, Any
from pathlib import Path


class CuckooSandbox:
    """
    Cuckoo Sandbox integration for dynamic malware analysis.

    Supports file submission, report retrieval, and behavior analysis.
    """

    def __init__(
        self, base_url: str = "http://localhost:8090", api_token: Optional[str] = None
    ):
        """
        Initialize Cuckoo Sandbox client.

        Args:
            base_url: Cuckoo REST API endpoint
            api_token: Optional API token for authentication
        """
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.headers = {}
        if api_token:
            self.headers["Authorization"] = f"Bearer {api_token}"

    def submit_file(self, file_path: str, timeout: int = 120) -> Optional[int]:
        """
        Submit a file to Cuckoo Sandbox for analysis.

        Args:
            file_path: Path to the file to analyze
            timeout: Analysis timeout in seconds

        Returns:
            Task ID if successful, None otherwise
        """
        try:
            with open(file_path, "rb") as f:
                files = {"file": (Path(file_path).name, f)}
                data = {"timeout": timeout}

                response = requests.post(
                    f"{self.base_url}/tasks/create/file",
                    files=files,
                    data=data,
                    headers=self.headers,
                    timeout=10,
                )

                if response.status_code == 200:
                    result = response.json()
                    return result.get("task_id")
                else:
                    print(f"[!] Cuckoo submit failed: {response.status_code}")
                    return None
        except Exception as e:
            print(f"[!] Cuckoo submit error: {e}")
            return None

    def get_report(self, task_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve analysis report for a task.

        Args:
            task_id: The task ID from submission

        Returns:
            Report dictionary if available, None otherwise
        """
        try:
            response = requests.get(
                f"{self.base_url}/tasks/report/{task_id}",
                headers=self.headers,
                timeout=10,
            )

            if response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception as e:
            print(f"[!] Cuckoo report error: {e}")
            return None

    def wait_for_report(
        self, task_id: int, max_wait: int = 300, poll_interval: int = 5
    ) -> Optional[Dict[str, Any]]:
        """
        Wait for analysis to complete and retrieve report.

        Args:
            task_id: The task ID from submission
            max_wait: Maximum wait time in seconds
            poll_interval: Seconds between status checks

        Returns:
            Report dictionary if successful, None if timeout or failure
        """
        start_time = time.time()

        while time.time() - start_time < max_wait:
            status = self.get_task_status(task_id)

            if status == "reported":
                return self.get_report(task_id)
            elif status in ["failed_analysis", "failed_processing"]:
                print(f"[!] Task {task_id} failed")
                return None

            time.sleep(poll_interval)

        print(f"[!] Timeout waiting for task {task_id}")
        return None

    def get_task_status(self, task_id: int) -> Optional[str]:
        """
        Get the current status of a task.

        Args:
            task_id: The task ID to check

        Returns:
            Status string (pending, running, completed, reported, etc.) or None
        """
        try:
            response = requests.get(
                f"{self.base_url}/tasks/view/{task_id}",
                headers=self.headers,
                timeout=10,
            )

            if response.status_code == 200:
                result = response.json()
                return result.get("task", {}).get("status")
            else:
                return None
        except Exception as e:
            print(f"[!] Cuckoo status error: {e}")
            return None

    def analyze_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse and summarize Cuckoo analysis report.

        Args:
            report: Raw Cuckoo report dictionary

        Returns:
            Structured behavior summary
        """
        behavior_summary: Dict[str, Any] = {
            "processes": [],
            "network": {
                "dns": [],
                "http": [],
                "tcp": [],
                "udp": [],
            },
            "files": {
                "created": [],
                "deleted": [],
                "modified": [],
            },
            "registry": {
                "created": [],
                "deleted": [],
                "modified": [],
            },
            "mutexes": [],
            "signatures": [],
            "score": 0.0,
        }

        try:
            # Parse process information
            if "behavior" in report:
                behavior = report["behavior"]

                if "processes" in behavior:
                    for proc in behavior["processes"]:
                        behavior_summary["processes"].append(
                            {
                                "name": proc.get("process_name"),
                                "pid": proc.get("process_id"),
                                "calls": len(proc.get("calls", [])),
                            }
                        )

                if "summary" in behavior:
                    summary = behavior["summary"]
                    behavior_summary["files"]["created"] = summary.get("files", [])
                    behavior_summary["registry"]["created"] = summary.get("keys", [])
                    behavior_summary["mutexes"] = summary.get("mutexes", [])

            # Parse network activity
            if "network" in report:
                network = report["network"]
                behavior_summary["network"]["dns"] = [
                    {
                        "domain": d.get("request"),
                        "ip": d.get("answers", [{}])[0].get("data"),
                    }
                    for d in network.get("dns", [])
                ]
                behavior_summary["network"]["http"] = [
                    {
                        "method": h.get("method"),
                        "uri": h.get("uri"),
                        "host": h.get("host"),
                    }
                    for h in network.get("http", [])
                ]
                behavior_summary["network"]["tcp"] = network.get("tcp", [])
                behavior_summary["network"]["udp"] = network.get("udp", [])

            # Parse signatures (behavioral indicators)
            if "signatures" in report:
                for sig in report["signatures"]:
                    behavior_summary["signatures"].append(
                        {
                            "name": sig.get("name"),
                            "description": sig.get("description"),
                            "severity": sig.get("severity"),
                        }
                    )

            # Extract overall score
            if "info" in report:
                behavior_summary["score"] = report["info"].get("score", 0.0)

        except Exception as e:
            print(f"[!] Report analysis error: {e}")

        return behavior_summary

    def quick_scan(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Perform a complete scan: submit, wait, and analyze.

        Args:
            file_path: Path to file to analyze

        Returns:
            Behavior summary dictionary or None if failed
        """
        print(f"[*] Submitting to Cuckoo: {file_path}")
        task_id = self.submit_file(file_path)

        if not task_id:
            return None

        print(f"[*] Task ID: {task_id} - Waiting for analysis...")
        report = self.wait_for_report(task_id)

        if not report:
            return None

        print("[+] Analysis complete!")
        return self.analyze_report(report)
