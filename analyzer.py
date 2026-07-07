# analyzer.py

def analyze_result(cmd_meta: dict, result: dict) -> dict:
    """
    Analyzes the output of a command to determine if there's a finding.
    Returns a dictionary with the analysis.
    """
    finding = {
        "id": cmd_meta["id"],
        "name": cmd_meta["name"],
        "category": cmd_meta["category"],
        "description": cmd_meta["description"],
        "command": cmd_meta["command"],
        "risk_level": cmd_meta["risk_level"],
        "remediation": cmd_meta["remediation"],
        "raw_output": result["stdout"],
        "status": "PASS",
        "notes": ""
    }

    # Handle Execution Errors (e.g., running on Windows or command not found)
    if result["error"] or (result["returncode"] != 0 and result["stderr"]):
        finding["status"] = "ERROR"
        err_msg = result["error"] if result["error"] else result["stderr"]
        finding["notes"] = f"Execution failed: {err_msg}"
        return finding

    # Specific analysis logic based on command ID
    stdout = result["stdout"]
    
    if cmd_meta["id"] == "CHK_ROOT_UID":
        lines = stdout.splitlines()
        # Expecting only root to have UID 0. e.g., root:x:0:0:root:/root:/bin/bash
        non_root_accounts = [line.split(":")[0] for line in lines if not line.startswith("root:")]
        if non_root_accounts:
            finding["status"] = "FAIL"
            finding["notes"] = f"Found non-root accounts with UID 0: {', '.join(non_root_accounts)}"
            
    elif cmd_meta["id"] == "CHK_EMPTY_PASSWORDS":
        if stdout:
            finding["status"] = "FAIL"
            finding["notes"] = "Accounts with empty passwords found."
            
    elif cmd_meta["id"] == "CHK_WORLD_WRITABLE":
        if stdout:
            finding["status"] = "FAIL"
            finding["notes"] = "World-writable files found in /etc."
            
    elif cmd_meta["id"] == "CHK_SSH_ROOT_LOGIN":
        if "yes" in stdout.lower():
            finding["status"] = "FAIL"
            finding["notes"] = "Root login is permitted via SSH."
            
    else:
        # For INFO level or generic commands (like checking open ports or SUID files),
        # we mark them as INFO, meaning manual review is needed.
        if stdout:
            finding["status"] = "INFO"
            finding["notes"] = "Data gathered for review."
        else:
            finding["status"] = "PASS"
            finding["notes"] = "No output/data."

    return finding
