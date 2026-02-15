import ollama
import subprocess
import os
import sys
import shutil
import time
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for PC terminal colors
init(autoreset=True)

# --- Configuration ---
MODEL = "llama3.1:8b"
BASE_OUTPUT_DIR = "recon_scans"

# --- System Prompt ---
SYSTEM_PROMPT = """
You are an expert Bug Bounty Reconnaissance Agent running locally on a PC.
Your job is to autonomously map out an attack surface.

YOUR TOOLKIT:
1. `run_subfinder`: Use this FIRST to find subdomains.
2. `run_httpx`: Use this SECOND to filter for live web servers.

PROTOCOL:
- Always start by creating a plan.
- Execute tools sequentially.
- Do not ask the user for permission to run the next tool; just do it.
- After httpx runs, summarize the findings (count of subs found, count of live hosts).
- If a tool fails, report the error and stop.
"""


class ReconAgent:
    def __init__(self, target_domain):
        self.target = target_domain
        self.scan_dir = os.path.join(BASE_OUTPUT_DIR, target_domain)
        self.subs_file = os.path.join(self.scan_dir, "subdomains.txt")
        self.live_file = os.path.join(self.scan_dir, "live_hosts.txt")
        self.history = [{'role': 'system', 'content': SYSTEM_PROMPT}]

        # Ensure output directory exists
        if not os.path.exists(self.scan_dir):
            os.makedirs(self.scan_dir)
            print(f"{Fore.GREEN}[+] Created scan directory: {self.scan_dir}")

    def _check_dependency(self, tool_name):
        """Checks if a tool is installed and in the system PATH."""
        if shutil.which(tool_name) is None:
            print(f"{Fore.RED}[!] ERROR: '{tool_name}' is not installed or not in PATH.")
            return False
        return True

    def run_subfinder(self) -> str:
        """Tool: Runs subfinder to discover subdomains."""
        if not self._check_dependency("subfinder"):
            return "Error: subfinder tool missing."

        print(f"\n{Fore.CYAN}[*] Launching Subfinder for {self.target}...")
        cmd = f"subfinder -d {self.target} -all -silent -o {self.subs_file}"

        try:
            # Run command and stream output slightly to show activity
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                line_count = 0
                with open(self.subs_file, 'r') as f:
                    line_count = sum(1 for _ in f)
                print(f"{Fore.GREEN}[+] Subfinder complete. Found {line_count} subdomains.")
                return f"Subfinder completed successfully. Saved {line_count} subdomains to {self.subs_file}."
            else:
                return f"Subfinder failed: {stderr}"
        except Exception as e:
            return f"Exception running subfinder: {str(e)}"

    def run_httpx(self) -> str:
        """Tool: Runs httpx to find live hosts from the subdomains list."""
        if not self._check_dependency("httpx"):
            return "Error: httpx tool missing."

        if not os.path.exists(self.subs_file):
            return "Error: No subdomains file found. Run subfinder first."

        print(f"\n{Fore.CYAN}[*] Launching HTTPX on {self.subs_file}...")
        # -sc gives status code, -title gives page title
        cmd = f"httpx -l {self.subs_file} -sc -title -silent -o {self.live_file}"

        try:
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                line_count = 0
                if os.path.exists(self.live_file):
                    with open(self.live_file, 'r') as f:
                        line_count = sum(1 for _ in f)
                print(f"{Fore.GREEN}[+] HTTPX complete. Found {line_count} live hosts.")
                return f"HTTPX completed. Saved {line_count} live hosts to {self.live_file}. Output snippet: {stdout[:200]}..."
            else:
                return f"HTTPX failed: {stderr}"
        except Exception as e:
            return f"Exception running httpx: {str(e)}"

    def start(self):
        print(f"{Fore.YELLOW}[*] Initializing Llama 3.1 Agent for target: {self.target}")
        self.history.append({'role': 'user', 'content': f"Start reconnaissance on {self.target}"})

        while True:
            # 1. Get response from LLM
            response = ollama.chat(
                model=MODEL,
                messages=self.history,
                tools=[self.run_subfinder, self.run_httpx]  # Explicit tools
            )

            message = response['message']
            self.history.append(message)

            # 2. Check for tool calls
            if message.get('tool_calls'):
                for tool in message['tool_calls']:
                    function_name = tool['function']['name']
                    print(f"{Fore.MAGENTA} -> AI Decided to call: {function_name}")

                    # Execute the appropriate Python function
                    tool_output = ""
                    if function_name == 'run_subfinder':
                        tool_output = self.run_subfinder()
                    elif function_name == 'run_httpx':
                        tool_output = self.run_httpx()

                    # 3. Send result back to LLM
                    self.history.append({
                        'role': 'tool',
                        'content': tool_output,
                    })
            else:
                # 4. Final response or question from AI
                print(f"\n{Fore.WHITE}AI Summary: {message['content']}")
                break


if __name__ == "__main__":
    try:
        # Clear screen for a fresh start
        os.system('cls' if os.name == 'nt' else 'clear')

        print(f"{Fore.RED}=== AUTOMATED RECON AGENT v2.0 ==={Style.RESET_ALL}")
        target_input = input("Enter target domain (e.g., tesla.com): ").strip()

        if target_input:
            agent = ReconAgent(target_input)
            agent.start()
        else:
            print("No target provided. Exiting.")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan aborted by user.")
        sys.exit()