#!/bin/bash

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# List of required dependencies (commands/packages)
DEPENDENCIES=(
    "curl"
    "wget"
    "build-essential"
    "libbpf-dev"
    "clang"
    "bpftool"
    "linux-headers-$(uname -r)"
)

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Script requires root privileges for package installation${NC}"
    echo -e "Please enter your password when prompted\n"
fi

# Function to check command availability
check_dependency() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}[OK]${NC} $1 is installed"
        return 0
    else
        echo -e "${RED}[MISSING]${NC} $1 not found"
        return 1
    fi
}

# Function to install package
install_package() {
    echo -e "${YELLOW}Attempting to install: $1...${NC}"
    apt-get install -y "$1" &> /dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully installed: $1${NC}"
        return 0
    else
        echo -e "${RED}Failed to install: $1${NC}"
        return 1
    fi
}

# Main dependency check
missing_deps=()
for dep in "${DEPENDENCIES[@]}"; do
    # First check if command exists
    if ! check_dependency "$dep"; then
        # If not found, try to find corresponding package
        pkg_name=$(apt-cache search --names-only "^${dep}$" | awk '{print $1}')
        
        if [ -n "$pkg_name" ]; then
            if ! install_package "$pkg_name"; then
                missing_deps+=("$dep")
            fi
        else
            echo -e "${RED}Cannot find package for: $dep${NC}"
            missing_deps+=("$dep")
        fi
    fi
done

# Final status check
if [ ${#missing_deps[@]} -gt 0 ]; then
    echo -e "\n${RED}Missing dependencies:"
    printf ' - %s\n' "${missing_deps[@]}"
    echo -e "\nPlease install manually and rerun the script${NC}"
    exit 1
else
    echo -e "\n${GREEN}All dependencies are satisfied!${NC}"
    exit 0
fi

