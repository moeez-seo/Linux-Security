# Linux Security Commands Audit Suite

## Overview
This is a **Python CLI project** designed as a **defensive and educational tool** to audit Linux systems. It organizes and runs common Linux security commands for user/account checks, file permissions, process monitoring, network inspection, and SSH review.

It analyzes the output of these commands and generates a comprehensive Markdown report with findings, explanations, and remediation recommendations.

## Features
* **Modular Architecture**: Commands are stored in a catalog (`command_catalog.py`), execution is handled safely (`executor.py`), and analysis is separated (`analyzer.py`).
* **Non-Intrusive**: Only runs read-only/reporting commands (like `ss`, `ps`, `cat`, `awk`). Does not alter system state.
* **Markdown Export**: Generates a clean, readable report (`linux_security_audit_report.md`).
* **Graceful Failure**: If a command is missing or the script is run on an incompatible OS (like Windows), it reports an Error status in the audit rather than crashing.

## Requirements
* Python 3.x
* A Linux Environment (Ubuntu, Debian, CentOS, WSL, etc.) to successfully run the commands. Running this on Windows will result in command execution errors (which the tool will catch and report).
* Root privileges (`sudo`) may be required for some commands to return meaningful data (e.g., checking `/etc/shadow` or `ss -tuln` for all processes).

## Usage
1. Open a terminal.
2. Navigate to the project directory.
3. Run the application (use `sudo` for best results):
   ```bash
   sudo python3 app.py
   ```
4. Follow the interactive menu to run audits.

## Disclaimer
This tool is strictly for educational and defensive purposes. It is meant to help users identify potential misconfigurations in their own Linux systems. It contains no offensive capabilities, exploits, or privilege escalation functionality.
