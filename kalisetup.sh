#!/bin/bash

set -euo pipefail  # Exit on undefined variables or errors in pipelines

echo "[*] Updating and upgrading system packages..."
sudo apt update && sudo apt upgrade -y

echo "[*] Ensuring Docker is installed..."
if ! command -v docker >/dev/null 2>&1; then
    sudo apt install -y docker.io
else
    echo "[*] Docker already installed."
fi

echo "[*] Ensuring Docker Compose is installed..."
if ! command -v docker-compose >/dev/null 2>&1; then
    echo "[*] Installing docker-compose binary manually..."
    version=$(wget -qO- https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    sudo wget -q -O /usr/local/bin/docker-compose "https://github.com/docker/compose/releases/download/${version}/docker-compose-$(uname -s)-$(uname -m)"
    sudo chmod +x /usr/local/bin/docker-compose
else
    echo "[*] Docker Compose already installed."
fi

echo "[*] Cleaning up historical data..."
sudo rm -Rf /Tools || true
sudo docker-compose -f /opt/bloodhoundce/docker-compose.yml down -v || true

echo "[*] Creating Tools directory..."
sudo mkdir -p /Tools/Wordlists
cd /Tools/Wordlists

echo "[*] Downloading wordlists..."
sudo wget -q https://softwaredl.stellar.tech/Software/xato-net-10-million-usernames.txt
sudo wget -q https://softwaredl.stellar.tech/Software/rockyou.txt

echo "[*] Downloading Kerbrute and SharpHound..."
cd /Tools
sudo wget -q https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
sudo chmod +x kerbrute_linux_amd64
sudo wget -q https://github.com/SpecterOps/SharpHound/releases/download/v2.6.3/SharpHound_v2.6.3_windows_x86.zip
sudo unzip -o SharpHound_v2.6.3_windows_x86.zip

echo "[*] Setting up BloodHound CE..."
sudo mkdir -p /opt/bloodhoundce
sudo wget -q -O /opt/bloodhoundce/docker-compose.yml https://ghst.ly/getbhce

echo "[*] Starting BloodHound CE via Docker Compose..."
sudo docker-compose -f /opt/bloodhoundce/docker-compose.yml up -d

echo "[*] Waiting for BloodHound CE to initialize..."
sleep 30

echo "[*] Retrieving initial BloodHound login password:"
sudo docker logs bloodhoundce-bloodhound-1 2>&1 | grep "Initial Password Set To:" || echo "[!] Could not retrieve password."

echo "[*] Enabling SSH socket..."
sudo systemctl enable ssh.socket
sudo systemctl start ssh.socket

echo "[✔] Setup complete."
echo "--------------------------------------"
echo "Login: http://localhost:8080/ui/login"
echo "Collectors: http://localhost:8080/ui/download-collectors"
echo "--------------------------------------"
