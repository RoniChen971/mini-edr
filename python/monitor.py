import argparse
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import sys
from pathlib import Path

def get_default_reports_dir() -> str:
    """Return the default reports directory (project-relative).

    This avoids embedding user-specific absolute paths in the code. The
    location can be overridden with the `MINIEDR_REPORT_DIR` environment
    variable or with the `--reports-dir` command-line argument.
    """
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    return str(repo_root / "reports")


# File paths (default to project-relative; can be overridden later)
DEFAULT_REPORTS_DIR = os.environ.get("MINIEDR_REPORT_DIR") or get_default_reports_dir()
REPORT_FILE = os.path.join(DEFAULT_REPORTS_DIR, "suspicious_processes.json")
OUTPUT_FILE = os.path.join(DEFAULT_REPORTS_DIR, "suspicious_processes_python.json")
SEEN_KEYS_FILE = os.path.join(DEFAULT_REPORTS_DIR, "seen_processes.json")

# Risk scoring rules
RISK_RULES = {
    "external_connection_suspicious_path": "HIGH",
    "external_connection_any": "HIGH",
    "invalid_signature_suspicious_path": "HIGH",
    "suspicious_path_unsigned": "MID",
    "suspicious_path": "MID",
    "unsigned_non_trusted": "MID",
    "default": "LOW"
}

SUSPICIOUS_FOLDERS = {"appdata", "temp", "downloads"}
TRUSTED_PATHS = {"c:\\program files", "c:\\windows"}


def load_seen_keys():
    """Load previously seen processes from persistent storage"""
    try:
        if os.path.exists(SEEN_KEYS_FILE):
            with open(SEEN_KEYS_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
    except Exception as e:
        print(f"[!] Could not load seen keys: {e}")
    return set()


def save_seen_keys(seen_keys):
    """Persist seen keys to disk"""
    try:
        with open(SEEN_KEYS_FILE, "w", encoding="utf-8") as f:
            json.dump(list(seen_keys), f, indent=2)
    except Exception as e:
        print(f"[!] Could not save seen keys: {e}")


def assess_risk(proc):
    """Unified risk assessment using scoring rules"""
    path = proc.get("Path", "").lower()
    is_external = proc.get("HasExternalConn", False)
    signature = proc.get("Signature", "Unknown")
    
    is_suspicious = any(folder in path for folder in SUSPICIOUS_FOLDERS)
    is_trusted = any(trusted in path for trusted in TRUSTED_PATHS)
    
    if is_external and is_suspicious:
        return RISK_RULES["external_connection_suspicious_path"]
    if is_external and not is_trusted:
        return RISK_RULES["external_connection_any"]
    if is_suspicious and signature == "Invalid":
        return RISK_RULES["invalid_signature_suspicious_path"]
    if is_suspicious and signature in ("Unknown", "Unsigned"):
        return RISK_RULES["suspicious_path_unsigned"]
    if is_suspicious:
        return RISK_RULES["suspicious_path"]
    if not is_trusted and signature in ("Unknown", 1, "Unsigned"):
        return RISK_RULES["unsigned_non_trusted"]
    
    return RISK_RULES["default"]


def consolidate_processes(processes):
    """Group processes by Name+Path and merge PIDs"""
    grouped = {}
    
    for proc in processes:
        key = f"{proc['Name']}|{proc['Path']}"
        
        if key not in grouped:
            grouped[key] = {
                "Timestamp": proc["Timestamp"],
                "Name": proc["Name"],
                "Path": proc["Path"],
                "Signature": proc.get("Signature", "Unknown"),
                "PIDs": [proc.get("PID")] if proc.get("PID") else [],
                "ExternalConnections": proc.get("ExternalConnections", []),
                "HasExternalConn": proc.get("HasExternalConn", False)
            }
        else:
            if proc.get("PID") and proc["PID"] not in grouped[key]["PIDs"]:
                grouped[key]["PIDs"].append(proc["PID"])
            if proc.get("ExternalConnections"):
                for conn in proc["ExternalConnections"]:
                    if conn and conn not in grouped[key]["ExternalConnections"]:
                        grouped[key]["ExternalConnections"].append(conn)
    
    return grouped


def process_suspicious_file(handler):
    """Process the suspicious_processes.json file"""
    try:
        with open(REPORT_FILE, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[!] File not found: {REPORT_FILE}")
        return
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON: {e}")
        return
    except Exception as e:
        print(f"[!] Error reading: {e}")
        return

    grouped = consolidate_processes(data)
    new_processes = []
    
    for key, proc in grouped.items():
        if key not in handler.seen_keys:
            handler.seen_keys.add(key)
            proc["Risk"] = assess_risk(proc)
            proc["PID_Count"] = len(proc["PIDs"])
            new_processes.append(proc)
    
    if new_processes:
        existing = []
        if os.path.exists(OUTPUT_FILE):
            try:
                with open(OUTPUT_FILE, "r", encoding="utf-8-sig") as f:
                    existing = json.load(f)
            except:
                pass
        
        existing.extend(new_processes)
        
        try:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)
            
            print(f"✓ Wrote {len(new_processes)} new process(es)")
            for proc in new_processes:
                risk = proc["Risk"]
                pids = proc["PIDs"]
                pid_str = f"PIDs {pids}" if len(pids) > 1 else f"PID {pids[0]}" if pids else "?"
                net = f" [NET: {len(proc['ExternalConnections'])} ext]" if proc["ExternalConnections"] else ""
                print(f"  {proc['Timestamp']} - {proc['Name']} ({pid_str}) [{risk}]{net}")
        except Exception as e:
            print(f"[!] Error writing: {e}")
    
    handler.save_state()


class JSONHandler(FileSystemEventHandler):
    """Watch for changes to suspicious_processes.json"""
    
    def __init__(self):
        self.seen_keys = load_seen_keys()
    
    def save_state(self):
        """Persist seen keys to disk"""
        save_seen_keys(self.seen_keys)
    
    def on_modified(self, event):
        if event.src_path.endswith("suspicious_processes.json"):
            process_suspicious_file(self)


def main():
    """Main entry point"""
    print("=" * 60)
    print("Mini EDR - Python Monitor")
    print("=" * 60)
    parser = argparse.ArgumentParser(description="MiniEDR Python monitor")
    parser.add_argument(
        "--reports-dir",
        help="Path to the reports directory (overrides MINIEDR_REPORT_DIR env var)",
        default=None,
    )
    args = parser.parse_args()

    # Allow runtime override of report paths
    reports_dir = args.reports_dir or os.environ.get("MINIEDR_REPORT_DIR") or get_default_reports_dir()
    global REPORT_FILE, OUTPUT_FILE, SEEN_KEYS_FILE
    REPORT_FILE = os.path.join(reports_dir, "suspicious_processes.json")
    OUTPUT_FILE = os.path.join(reports_dir, "suspicious_processes_python.json")
    SEEN_KEYS_FILE = os.path.join(reports_dir, "seen_processes.json")

    # Ensure the reports directory exists
    try:
        Path(reports_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[!] Could not create reports directory {reports_dir}: {e}")
        sys.exit(1)

    # Initialize handler with persistent state
    handler = JSONHandler()
    print(f"[+] Loaded {len(handler.seen_keys)} previously seen processes")

    print("[*] Processing initial data...")
    process_suspicious_file(handler)
    
    # Start file watcher
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(REPORT_FILE), recursive=False)
    observer.start()
    print("[+] Watching for changes. Press Ctrl+C to stop.\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        observer.stop()
    
    observer.join()
    print("[+] Done")


if __name__ == "__main__":
    main()
