# executor.py
import subprocess

def run_command(command_string: str) -> dict:
    """
    Executes a shell command and returns the standard output, standard error, and return code.
    Handles exceptions if the command cannot be found or executed (e.g., on Windows).
    """
    try:
        # shell=True is needed to evaluate pipelines (e.g., awk, grep) used in our catalog
        result = subprocess.run(
            command_string,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30 # Prevent hanging commands
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
            "error": None
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "error": str(e)
        }
