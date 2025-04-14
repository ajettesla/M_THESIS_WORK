#!/usr/bin/env python3
import requests
import time
import sys
import os
import argparse
import daemon
import lockfile
from datetime import datetime

# Netdata API base URL
NETDATA_URL = "http://localhost:19999/api/v1/data"

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Monitor program resources with Netdata")
parser.add_argument("-p", "--program", required=True, help="Program name (e.g., firefox)")
parser.add_argument("-l", "--logfile", default="resource.log", help="Log file path")
parser.add_argument("-d", "--daemon", action="store_true", help="Run as daemon")
parser.add_argument("-k", "--kill", action="store_true", help="Kill all running daemons")
args = parser.parse_args()

# Daemon PID file
PID_FILE = f"/tmp/monitor_{args.program}.pid"

def get_resource_usage(program):
    """Fetch CPU, memory, and network usage from Netdata API."""
    # CPU usage (percentage)
    cpu_url = f"{NETDATA_URL}?chart=apps_cpu&dimension={program}&format=json&points=1&after=-1"
    cpu_resp = requests.get(cpu_url)
    cpu_data = cpu_resp.json()
    cpu_usage = cpu_data["data"][0][1] if cpu_data["data"] else 0.0

    # Memory usage (bytes)
    mem_url = f"{NETDATA_URL}?chart=apps_mem&dimension={program}&format=json&points=1&after=-1"
    mem_resp = requests.get(mem_url)
    mem_data = mem_resp.json()
    mem_usage = mem_data["data"][0][1] * 1024 if mem_data["data"] else 0  # Convert KB to bytes

    # Network usage (bytes/s sent and received)
    net_url = f"{NETDATA_URL}?chart=apps_net&dimension={program}&format=json&points=1&after=-1"
    net_resp = requests.get(net_url)
    net_data = net_resp.json()
    net_sent = net_data["data"][0][1] if net_data["data"] else 0  # Bytes/s sent
    net_received = net_data["data"][0][2] if net_data["data"] else 0  # Bytes/s received

    return cpu_usage, mem_usage, net_sent, net_received

def log_and_print(program, logfile, daemon_mode):
    """Monitor and log resource usage."""
    while True:
        cpu, mem, net_sent, net_received = get_resource_usage(program)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (f"{timestamp}, CPU: {cpu:.2f}%, "
                     f"Memory: {mem/1024/1024:.2f} MB, "
                     f"Net Sent: {net_sent/1024:.2f} KB/s, "
                     f"Net Received: {net_received/1024:.2f} KB/s\n")

        # Write to log file
        with open(logfile, "a") as f:
            f.write(log_entry)

        # Print to stdout if not in daemon mode
        if not daemon_mode:
            print(log_entry.strip())

        time.sleep(1)

def kill_daemons():
    """Kill all running monitor daemons."""
    if os.path.exists(PID_FILE):
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, 9)  # SIGKILL
            os.remove(PID_FILE)
            print(f"Killed daemon with PID {pid}")
        except ProcessLookupError:
            print("No daemon running or PID file stale. Removed PID file.")
            os.remove(PID_FILE)
    else:
        print("No daemon running.")
    sys.exit(0)

if __name__ == "__main__":
    if args.kill:
        kill_daemons()

    if os.path.exists(PID_FILE) and args.daemon:
        print("Daemon already running. Use -k to kill it first.")
        sys.exit(1)

    if args.daemon:
        with daemon.DaemonContext(
            pidfile=lockfile.FileLock(PID_FILE),
            working_directory=os.getcwd(),
            umask=0o002,
        ):
            log_and_print(args.program, args.logfile, True)
    else:
        log_and_print(args.program, args.logfile, False)
