# app.py
import sys
from command_catalog import COMMANDS
from executor import run_command
from analyzer import analyze_result
from reports import generate_markdown_report

def print_header():
    print("\n" + "="*60)
    print(" Linux Security Commands Audit Suite ".center(60))
    print("="*60)
    print(" Educational & Defensive Use Only ".center(60))
    print("="*60 + "\n")

def run_audit(category=None):
    print("\n[+] Starting Audit...")
    
    cmds_to_run = COMMANDS
    if category:
        cmds_to_run = [c for c in COMMANDS if c["category"] == category]
        
    findings = []
    
    for cmd_meta in cmds_to_run:
        print(f" [*] Running: {cmd_meta['name']}...")
        result = run_command(cmd_meta['command'])
        analysis = analyze_result(cmd_meta, result)
        findings.append(analysis)
        
        status = analysis["status"]
        if status == "PASS":
            print("     [+] PASS")
        elif status == "FAIL":
            print(f"     [-] FAIL: {analysis['notes']}")
        elif status == "INFO":
            print("     [i] INFO: Needs review.")
        elif status == "ERROR":
            print(f"     [!] ERROR: {analysis['notes']}")
            
    print("\n[+] Audit Complete.")
    
    try:
        report_path = generate_markdown_report(findings)
        print(f"[+] Report generated at:\n    {report_path}")
    except Exception as e:
        print(f"[-] Failed to generate report: {e}")

def main():
    while True:
        print_header()
        print("1. Run Full Security Audit")
        print("2. User/Account Checks Only")
        print("3. File Permissions Checks Only")
        print("4. Network & Process Checks Only")
        print("5. Exit")
        
        choice = input("\nSelect an option (1-5): ").strip()
        
        if choice == '1':
            run_audit()
        elif choice == '2':
            run_audit("User/Account Checks")
        elif choice == '3':
            run_audit("File Permissions")
        elif choice == '4':
            run_audit("Network Inspection")
            run_audit("Process Monitoring")
        elif choice == '5':
            print("\nExiting. Stay secure!")
            sys.exit(0)
        else:
            print("\n[-] Invalid choice. Please select 1-5.")
            
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
