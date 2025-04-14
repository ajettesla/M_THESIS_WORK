#!/usr/bin/env python3
import argparse
import psutil
import time
import datetime
import os
import sys
import signal

def monitor_process(program_name, log_file):
    # Find the first process whose name matches the given program name.
    target_proc = None
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == program_name:
            target_proc = proc
            break
    if not target_proc:
        print(f"Error: Process '{program_name}' not found.")
        sys.exit(1)

    # Open log file if provided (we’ll log to both stdout and file if not in daemon mode)
    log_fh = open(log_file, 'a') if log_file else None

    # Print header (time, cpu, memory, network)
    header = "time, cpu (%), memory (MB), network (KB/s)"
    print(header)
    if log_fh:
        log_fh.write(header + "\n")
        log_fh.flush()

    # Get initial system-wide network counters.
    net_before = psutil.net_io_counters()
    last_time = time.time()

    while True:
        try:
            # Block 1 second to measure CPU percentage for the process.
            cpu = target_proc.cpu_percent(interval=1)
            mem = target_proc.memory_info().rss / (1024 * 1024)  # Convert bytes to MB

            # Get updated network counters and calculate difference.
            net_after = psutil.net_io_counters()
            now = time.time()
            dt = now - last_time
            total_before = net_before.bytes_recv + net_before.bytes_sent
            total_after = net_after.bytes_recv + net_after.bytes_sent
            net_delta = total_after - total_before
            net_rate = (net_delta / 1024.0) / dt  # KB per second

            # Update baseline for next iteration.
            net_before = net_after
            last_time = now

            # Format timestamp in ISO format.
            timestamp = datetime.datetime.now().isoformat()
            line = f"{timestamp}, {cpu:.2f}, {mem:.2f}, {net_rate:.2f}"
            print(line)
            if log_fh:
                log_fh.write(line + "\n")
                log_fh.flush()

        except psutil.NoSuchProcess:
            print("Target process terminated.")
            break
        except Exception as e:
            print(f"Error: {e}")
            break

def kill_daemons():
    """Kill all running monitor.py processes launched in daemon mode (-d)."""
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            cmdline = proc.info['cmdline']
            # Look for monitor.py with a '-d' argument in the command line.
            if cmdline and 'monitor.py' in cmdline[0] and '-d' in cmdline:
                if proc.pid != current_pid:
                    os.kill(proc.pid, signal.SIGTERM)
                    print(f"Killed daemon with PID {proc.pid}")
        except Exception:
            pass

def daemonize():
    """Daemonize the current process using a double-fork."""
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    # Redirect standard file descriptors.
    sys.stdout.flush()
    sys.stderr.flush()
    with open('/dev/null', 'r') as dev_null:
        os.dup2(dev_null.fileno(), sys.stdin.fileno())
    # Note: stdout and stderr redirection will be handled below if a log file is specified.

def main():
    parser = argparse.ArgumentParser(
        description="Monitor a running program's CPU, memory, and network usage."
    )
    parser.add_argument("-p", help="Program name to monitor", type=str)
    parser.add_argument("-l", help="Log file for output", type=str, default=None)
    parser.add_argument("-d", help="Run in daemon mode", action="store_true")
    parser.add_argument("-k", help="Kill all running daemon instances", action="store_true")
    args = parser.parse_args()

    if args.k:
        kill_daemons()
        sys.exit(0)

    if not args.p:
        parser.print_help()
        sys.exit(1)

    if args.d:
        daemonize()
        # If a log file is provided, redirect stdout and stderr to it.
        if args.l:
            log_fd = os.open(args.l, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            os.dup2(log_fd, sys.stdout.fileno())
            os.dup2(log_fd, sys.stderr.fileno())

    monitor_process(args.p, args.l)

if __name__ == "__main__":
    main()

