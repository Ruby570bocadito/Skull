#!/bin/bash

# SKULL-NetRecon Installation Script for Linux/macOS
# Run with: bash install.sh

echo "==============================================="
echo "  SKULL-NetRecon Installation Script"
echo "==============================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check Python installation
echo -e "${YELLOW}[*] Checking Python installation...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}[+] Python $PYTHON_VERSION found${NC}"
else
    echo -e "${RED}[!] Python 3 not found. Please install Python 3.8 or higher.${NC}"
    exit 1
fi

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}[!] pip3 not found. Please install pip.${NC}"
    exit 1
fi

# Create necessary directories
echo -e "\n${YELLOW}[*] Creating directories...${NC}"
for dir in logs reports; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        echo -e "${GREEN}[+] Created: $dir${NC}"
    else
        echo -e "${CYAN}[*] Directory exists: $dir${NC}"
    fi
done

# Install Python dependencies
echo -e "\n${YELLOW}[*] Installing Python dependencies...${NC}"
echo -e "${YELLOW}[!] This may take a few minutes...${NC}"

pip3 install --upgrade pip > /dev/null 2>&1

if pip3 install -r requirements.txt; then
    echo -e "${GREEN}[+] Dependencies installed successfully${NC}"
else
    echo -e "${RED}[!] Some dependencies failed to install${NC}"
    echo -e "${YELLOW}[*] You may need to install them manually${NC}"
fi

# Make main script executable
chmod +x skull_netrecon.py 2>/dev/null

# Verify installation
echo -e "\n${YELLOW}[*] Verifying installation...${NC}"

MODULES=("scapy" "rich" "yaml" "jinja2" "requests" "netifaces")
ALL_INSTALLED=true

for module in "${MODULES[@]}"; do
    if python3 -c "import $module" 2>/dev/null; then
        echo -e "${GREEN}[+] $module installed${NC}"
    else
        echo -e "${RED}[!] $module not found${NC}"
        ALL_INSTALLED=false
    fi
done

# Final status
echo ""
echo "==============================================="

if [ "$ALL_INSTALLED" = true ]; then
    echo -e "${GREEN}[+] Installation completed successfully!${NC}"
    echo -e "\n${YELLOW}You can now run SKULL-NetRecon:${NC}"
    echo -e "  ${NC}python3 skull_netrecon.py --target <TARGET>${NC}"
    echo -e "\n${YELLOW}For help:${NC}"
    echo -e "  ${NC}python3 skull_netrecon.py --help${NC}"
else
    echo -e "${RED}[!] Installation completed with errors${NC}"
    echo -e "${YELLOW}Please install missing dependencies manually${NC}"
fi

echo "==============================================="
echo ""

# Important notes
echo -e "${RED}IMPORTANT NOTES:${NC}"
echo -e "  ${YELLOW}- Some features require root privileges (use sudo)${NC}"
echo -e "  ${YELLOW}- Always obtain authorization before scanning${NC}"
echo -e "  ${YELLOW}- Review LEGAL.md for legal information${NC}"
echo ""
