#!/usr/bin/env python3

import argparse
import subprocess
import psutil
import time
import os
import sys
import signal
from datetime import datetime

# File to store daemon PID
PID_FILE = "/tmp/monitor_daemon.pid"

def get_pids(process_name):
    """Get all PIDs for a given process name."""
    return [p.pid for p in psutil.process_iter(['pid', 'name']) if p.info['name'].lower() == process_name.lower()]

def run_sysdig(chisel, pid):
    """Run Sysdig with a chisel for a specific PID and return output."""
    cmd = f"sudo -n sysdig -n 100 -c {chisel} proc.pid={pid}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        if result.stderr:
            raise Exception(f"Sysdig error: {result.stderr}")
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""  # Return empty string on timeout
    except Exception as e:
        raise Exception(f"Command failed: {str(e)}")

def parse_sysdig_output(output, metric_type):
    """Parse Sysdig output and extract network metric."""
    lines = output.splitlines()
    if not lines or len(lines) < 2:
        return 0
    # Assuming second line has data (skip header)
    data = lines[1].split()
    try:
        if metric_type == "net":
            value_str = data[1]  # Network bytes (e.g., 1.2K, 5.3M)
            return convert_to_kb(value_str)
    except (IndexError, ValueError):
        return 0

def convert_to_kb(value_str):
    """Convert network bytes to KB."""
    if not value_str:
        return 0
    # Extract numeric part, handling decimal points
    numeric_part = ''.join(c for c in value_str if c.isdigit() or c == '.')
    value = float(numeric_part)
    if "K" in value_str.upper():
        return value
    elif "M" in value_str.upper():
        return value * 1024
    elif "G" in value_str.upper():
        return value * 1024 * 1024
    else:  # Assume bytes
        return value / 1024

def monitor_process(process_name, log_file, daemonize):
    """Monitor CPU, memory, and network usage for a process."""
    if daemonize:
        daemonize_process()
    
    with open(log_file, "a") as log:
        while True:
            try:
                pids = get_pids(process_name)
                if not pids:
                    msg = f"{datetime.now()} - No PIDs found for {process_name}\n"
                    log.write(msg)
                    if not daemonize:
                        sys.stdout.write(msg)
                        sys.stdout.flush()
                    time.sleep(1)
                    continue

                total_cpu = 0
                total_mem = 0
                total_net = 0

                for pid in pids:
                    try:
                        p = psutil.Process(pid)
                        # CPU usage over 0.1s interval
                        total_cpu += p.cpu_percent(interval=0.1)
                        # Memory usage in MB
                        total_mem += p.memory_info().rss / (1024 * 1024)
                    except psutil.NoSuchProcess:
                        continue

                    # Network usage via Sysdig
                    net_out = run_sysdig("topprocs_net", pid)
                    total_net += parse_sysdig_output(net_out, "net")

                # Format output
                output = (
                    f"{datetime.now()} - {process_name} (PIDs: {len(pids)})\n"
                    f"CPU: {total_cpu:.2f}%\n"
                    f"Memory: {total_mem:.2f} MB\n"
                    f"Network: {total_net:.2f} KB\n"
                    "------------------------\n"
                )
                
                log.write(output)
                log.flush()
                if not daemonize:
                    sys.stdout.write(output)
                    sys.stdout.flush()
                
                time.sleep(1)  # Update every second
            except KeyboardInterrupt:
                if not daemonize:
                    sys.exit(0)
            except Exception as e:
                error_msg = f"{datetime.now()} - Error: {str(e)}\n"
                log.write(error_msg)
                if not daemonize:
                    sys.stdout.write(error_msg)
                    sys.stdout.flush()
                time.sleep(1)

def daemonize_process():
    """Daemonize the process."""
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    with open("/dev/null", "r") as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

def kill_daemon():
    """Kill the running daemon."""
    if not os.path.exists(PID_FILE):
        print("No daemon running.")
        sys.exit(1)
    with open(PID_FILE, "r") as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        os.remove(PID_FILE)
        print(f"Daemon (PID {pid}) terminated.")
    except ProcessLookupError:
        print("Daemon already terminated.")
        os.remove(PID_FILE)

def main():
    parser = argparse.ArgumentParser(description="Monitor process CPU, memory, and network usage.")
    parser.add_argument("-l", "--log", required=False, help="Log file path")
    parser.add_argument("-p", "--process", required=False, help="Process name to monitor")
    parser.add_argument("-d", "--daemonize", action="store_true", help="Run as daemon")
    parser.add_argument("-k", "--kill", action="store_true", help="Kill the daemon")
    
    args = parser.parse_args()

    if args.kill:
        kill_daemon()
        sys.exit(0)

    if not args.log or not args.process:
        parser.error("Both --log and --process are required unless --kill is specified.")

    monitor_process(args.process, args.log, args.daemonize)

if __name__ == "__main__":
    main()
