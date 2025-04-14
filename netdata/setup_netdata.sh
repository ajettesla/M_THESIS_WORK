#!/bin/bash

# Check if program name is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <program_name>"
    echo "Example: $0 firefox"
    exit 1
fi

PROGRAM_NAME="$1"

# Install Netdata
echo "Installing Netdata..."
bash <(curl -Ss https://my-netdata.io/kickstart.sh) --no-updates

# Verify installation
if ! command -v netdata &> /dev/null; then
    echo "Netdata installation failed!"
    exit 1
fi

# Ensure Netdata service is running
sudo systemctl enable netdata
sudo systemctl start netdata

# Configure apps_groups.conf for the program
NETDATA_CONF_DIR="/etc/netdata"
APPS_GROUPS_FILE="$NETDATA_CONF_DIR/apps_groups.conf"

if [ ! -f "$APPS_GROUPS_FILE" ]; then
    echo "Creating $APPS_GROUPS_FILE..."
    sudo touch "$APPS_GROUPS_FILE"
fi

# Add or update the program in apps_groups.conf
echo "Configuring Netdata to monitor $PROGRAM_NAME..."
if grep -q "^$PROGRAM_NAME:" "$APPS_GROUPS_FILE"; then
    sudo sed -i "s/^$PROGRAM_NAME:.*/$PROGRAM_NAME: $PROGRAM_NAME/" "$APPS_GROUPS_FILE"
else
    echo "$PROGRAM_NAME: $PROGRAM_NAME" | sudo tee -a "$APPS_GROUPS_FILE"
fi

# Restart Netdata to apply changes
sudo systemctl restart netdata

echo "Netdata installed and configured for $PROGRAM_NAME."
echo "Access the dashboard at http://localhost:19999"
