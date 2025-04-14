#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
import signal
import threading

def kill_monitors():
    """Kill all monitor.py processes except the current one."""
    try:
        output = subprocess.check_output(["pgrep", "-f", "monitor.py"], text=True)
        pids = [int(pid) for pid in output.split()]
    except subprocess.CalledProcessError:
        print("No monitor.py process found.")
        return

    current_pid = os.getpid()
    killed = 0
    for pid in pids:
        if pid != current_pid:
            try:
                os.kill(pid, signal.SIGTERM)
                killed += 1
            except Exception as e:
                print(f"Error killing process {pid}: {e}")
    print(f"Killed {killed} monitor.py process(es).")

def log_stderr(proc):
    """Thread function to log stderr from sysdig."""
    while True:
        err_line = proc.stderr.readline()
        if not err_line:
            break
        sys.stderr.write("[sysdig stderr] " + err_line)

def run_monitor(process_name, log_file=None, daemon=False):
    """Run sysdig with a chisel to monitor network usage for the given process."""
    cmd = ["sudo", "sysdig", "-c", "spy_process_name", process_name]

    if daemon:
        # In daemon mode, output is not printed to stdout.
        stdout_dest = open(log_file, "w") if log_file else open(os.devnull, "w")
        proc = subprocess.Popen(cmd, stdout=stdout_dest, stderr=subprocess.PIPE, text=True)
        # Optionally log errors from stderr in a separate thread.
        err_thread = threading.Thread(target=log_stderr, args=(proc,), daemon=True)
        err_thread.start()
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
        stdout_dest.close()
    else:
        # In non-daemon mode, print output to stdout and also log if a log file is provided.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Start a thread to print any errors from stderr.
        err_thread = threading.Thread(target=log_stderr, args=(proc,), daemon=True)
        err_thread.start()
        log_f = open(log_file, "w") if log_file else None
        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                print(line, end='')  # Print to stdout.
                if log_f:
                    log_f.write(line)
        except KeyboardInterrupt:
            proc.terminate()
            print("Monitoring interrupted by user.")
        if log_f:
            log_f.close()

def main():
    parser = argparse.ArgumentParser(
        description="Monitor network usage for a specific process using sysdig and eBPF."
    )
    parser.add_argument("-p", "--process", help="Process name to monitor (e.g., firefox)")
    parser.add_argument("-l", "--log", help="Log file to write output")
    parser.add_argument("-d", "--daemon", action="store_true",
                        help="Run in daemon mode (do not output logs to stdout)")
    parser.add_argument("-k", "--kill", action="store_true",
                        help="Kill all running monitor.py processes")
    args = parser.parse_args()

    if args.kill:
        kill_monitors()
        sys.exit(0)

    if not args.process:
        print("Error: Please specify a process to monitor using -p.")
        sys.exit(1)

    print(f"Monitoring network usage for process: {args.process}")
    if args.log:
        print(f"Logging output to: {args.log}")
    if args.daemon:
        print("Running in daemon mode (no stdout logging).")
    else:
        print("Output will be printed to stdout and logged to file if specified.")

    run_monitor(args.process, args.log, args.daemon)

if __name__ == "__main__":
    main()

