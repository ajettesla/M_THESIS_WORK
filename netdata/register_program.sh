#!/bin/bash

# Default resources
MONITOR_CPU=false
MONITOR_MEMORY=false
MONITOR_NETWORK=false

# Parse arguments
while getopts "p:cnm" opt; do
    case $opt in
        p) PROGRAM_NAME="$OPTARG";;
        c) MONITOR_CPU=true;;
        m) MONITOR_MEMORY=true;;
        n) MONITOR_NETWORK=true;;
        ?) echo "Usage: $0 -p <program_name> [-c] [-m] [-n]"
           echo "  -p: Program name (required)"
           echo "  -c: Monitor CPU"
           echo "  -m: Monitor Memory"
           echo "  -n: Monitor Network"
           exit 1;;
    esac
done

# Check if program name is provided
if [ -z "$PROGRAM_NAME" ]; then
    echo "Error: Program name required with -p"
    echo "Usage: $0 -p <program_name> [-c] [-m] [-n]"
    exit 1
fi

# Check if at least one resource is selected
if [ "$MONITOR_CPU" = false ] && [ "$MONITOR_MEMORY" = false ] && [ "$MONITOR_NETWORK" = false ]; then
    echo "Error: At least one resource (-c, -m, -n) must be specified"
    exit 1
fi

# Update apps_groups.conf
NETDATA_CONF_DIR="/etc/netdata"
APPS_GROUPS_FILE="$NETDATA_CONF_DIR/apps_groups.conf"

if [ ! -f "$APPS_GROUPS_FILE" ]; then
    echo "Error: $APPS_GROUPS_FILE not found. Run setup_netdata.sh first."
    exit 1
fi

echo "Registering $PROGRAM_NAME for monitoring..."
if grep -q "^$PROGRAM_NAME:" "$APPS_GROUPS_FILE"; then
    sudo sed -i "s/^$PROGRAM_NAME:.*/$PROGRAM_NAME: $PROGRAM_NAME/" "$APPS_GROUPS_FILE"
else
    echo "$PROGRAM_NAME: $PROGRAM_NAME" | sudo tee -a "$APPS_GROUPS_FILE"
fi

# Restart Netdata
sudo systemctl restart netdata

echo "$PROGRAM_NAME registered for:"
[ "$MONITOR_CPU" = true ] && echo "- CPU"
[ "$MONITOR_MEMORY" = true ] && echo "- Memory"
[ "$MONITOR_NETWORK" = true ] && echo "- Network"
