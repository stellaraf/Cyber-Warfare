#!/bin/bash

set -e  # Exit on error

echo "[*] Installing Docker and Docker Compose..."
sudo apt install -y docker.io docker-compose

echo "[*] Downloading latest Docker Compose manually..."
version=$(wget -qO- https://api.github.com/repos/docker/compose/releases/latest | grep -v "central-infosec" | grep '"tag_name"' | cut -d'"' -f4)
sudo wget -q -O /usr/local/bin/docker-compose "https://github.com/docker/compose/releases/download/${version}/docker-compose-$(uname -s)-$(uname -m)"
sudo chmod +x /usr/local/bin/docker-compose

echo "[*] Cleaning up any historical folders, files, and installations"
sudo rm -Rf /Tools
sudo docker-compose -f /opt/bloodhoundce/docker-compose.yml down -v

echo "[*] Updating and upgrading system packages..."
sudo apt update
sudo apt upgrade -y

echo "[*] Creating directories..."
sudo mkdir -p /Tools/Wordlists
cd /Tools/Wordlists

echo "[*] Downloading username wordlist from Stellar Cloudflare R2..."
sudo wget -q https://softwaredl.stellar.tech/Software/xato-net-10-million-usernames.txt

echo "[*] Downloading rockyou.txt from Stellar Cloudflare R2..."
sudo wget -q https://softwaredl.stellar.tech/Software/rockyou.txt

echo "[*] Downloading Kerbrute and SharpHound..."
cd /Tools
sudo wget -q https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
sudo chmod +x kerbrute_linux_amd64
sudo wget -q https://github.com/SpecterOps/SharpHound/releases/download/v2.6.3/SharpHound_v2.6.3_windows_x86.zip
sudo unzip SharpHound_v2.6.3_windows_x86.zip

echo "[*] Setting up BloodHound CE with Docker..."
sudo mkdir -p /opt/bloodhoundce
sudo wget -q -O /opt/bloodhoundce/docker-compose.yml https://ghst.ly/getbhce

echo "[*] Starting BloodHound CE using Docker Compose..."
sudo docker-compose -f /opt/bloodhoundce/docker-compose.yml up -d

echo "[*] Waiting for BloodHound to initialize (30s)..."
sleep 30

echo "[*] Retrieving initial login password for BloodHound..."
sudo docker logs bloodhoundce-bloodhound-1 2>&1 | grep "Initial Password Set To:"

sudo systemctl enable ssh.socket
sudo systemctl start ssh.socket

echo "[*] Setup complete."
echo "--------------------------------------"
echo "Login: http://localhost:8080/ui/login"
echo "Collectors: http://localhost:8080/ui/download-collectors"
echo "--------------------------------------"