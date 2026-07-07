# command_catalog.py

"""
Catalog of Linux commands used for the security audit.
Each command belongs to a category and includes metadata for analysis.
"""

COMMANDS = [
    # User and Account Checks
    {
        "id": "CHK_ROOT_UID",
        "category": "User/Account Checks",
        "name": "Check for multiple root accounts",
        "command": "awk -F: '($3 == \"0\") {print}' /etc/passwd",
        "description": "Checks if any account other than 'root' has a UID of 0.",
        "risk_level": "CRITICAL",
        "remediation": "Remove or change the UID of any non-root account with UID 0."
    },
    {
        "id": "CHK_EMPTY_PASSWORDS",
        "category": "User/Account Checks",
        "name": "Check for empty passwords",
        "command": "awk -F: '($2 == \"\" ) { print $1 \" does not have a password\"}' /etc/shadow 2>/dev/null",
        "description": "Identifies accounts with no password set in /etc/shadow.",
        "risk_level": "CRITICAL",
        "remediation": "Set passwords for these accounts or lock them."
    },
    
    # File Permissions
    {
        "id": "CHK_WORLD_WRITABLE",
        "category": "File Permissions",
        "name": "Find world-writable files in /etc",
        "command": "find /etc -type f -perm -0002 2>/dev/null",
        "description": "Locates configuration files that anyone can modify.",
        "risk_level": "HIGH",
        "remediation": "Remove write permissions for 'others' on critical system files (chmod o-w)."
    },
    {
        "id": "CHK_SUID_FILES",
        "category": "File Permissions",
        "name": "List SUID root files",
        "command": "find / -user root -perm -4000 -print 2>/dev/null | head -n 20",
        "description": "Lists the first 20 SUID binaries owned by root.",
        "risk_level": "MEDIUM",
        "remediation": "Review the list. Remove SUID bit from binaries that don't need it."
    },

    # Network Inspection
    {
        "id": "CHK_OPEN_PORTS",
        "category": "Network Inspection",
        "name": "List listening TCP/UDP ports",
        "command": "ss -tuln",
        "description": "Shows which services are listening for incoming network connections.",
        "risk_level": "INFO",
        "remediation": "Review open ports and close any unnecessary services via firewall or stopping the service."
    },
    
    # Process Monitoring
    {
        "id": "CHK_ROOT_PROCESSES",
        "category": "Process Monitoring",
        "name": "List processes running as root",
        "command": "ps -ef | awk '$1==\"root\" {print $2, $8}' | head -n 10",
        "description": "Shows a sample of processes running with root privileges.",
        "risk_level": "INFO",
        "remediation": "Ensure only necessary processes run as root. Consider running services as unprivileged users."
    },
    
    # SSH Configuration
    {
        "id": "CHK_SSH_ROOT_LOGIN",
        "category": "SSH Configuration",
        "name": "Check SSH Root Login",
        "command": "grep -i '^PermitRootLogin' /etc/ssh/sshd_config",
        "description": "Checks if direct root login via SSH is permitted.",
        "risk_level": "HIGH",
        "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config."
    }
]
