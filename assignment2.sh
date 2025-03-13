#!/bin/bash
# Assignment 2 Script 
# Created by Sher ALi

set -e  # Exit on error
set -o pipefail  # Catch pipeline errors

echo "Starting system configuration..."

# Configure Network (Ensure 192.168.16.21 is set)
NETPLAN_FILE="/etc/netplan/50-cloud-init.yaml"
TARGET_IP="192.168.16.21/24"
GATEWAY_IP="192.168.16.1"
DNS_SERVERS="8.8.8.8 1.1.1.1 9.9.9.9"  # Added fallback DNS

if ! grep -q "$TARGET_IP" "$NETPLAN_FILE"; then
    echo "Configuring network..."
    cat <<EOF | sudo tee "$NETPLAN_FILE" > /dev/null
network:
  ethernets:
    eth0:
      addresses:
        - $TARGET_IP
      gateway4: $GATEWAY_IP
      nameservers:
        addresses: [$DNS_SERVERS]
  version: 2
EOF
    sudo netplan apply
    echo "Network configuration updated."
else
    echo "Network is already correctly configured."
fi

# Ensure correct default route is set
if ! ip route | grep -q "default via $GATEWAY_IP"; then
    echo "Setting up default route..."
    sudo ip route add default via $GATEWAY_IP dev eth0
fi

# Update /etc/hosts
if ! grep -q "192.168.16.21 server1" /etc/hosts; then
    echo "Updating /etc/hosts..."
    sudo sed -i '/server1/d' /etc/hosts
    echo "192.168.16.21 server1" | sudo tee -a /etc/hosts > /dev/null
    echo "/etc/hosts updated."
else
    echo "/etc/hosts already contains the correct entry."
fi

# Verify Internet Connectivity
echo "Checking internet connection..."
if ! ping -c 4 8.8.8.8 >/dev/null 2>&1; then
    echo "No internet connection detected. Attempting to fix..."
    sudo systemctl restart networking
    sleep 3
    if ! ping -c 4 8.8.8.8 >/dev/null 2>&1; then
        echo "ERROR: Network is still unreachable. Please check manually."
        exit 1
    else
        echo "Internet connection restored."
    fi
else
    echo "Internet connection is active."
fi

# Test DNS Resolution
if ! nslookup archive.ubuntu.com >/dev/null 2>&1; then
    echo "DNS resolution is failing. Fixing..."
    echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
    echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf > /dev/null
fi

# Force APT update with retry
echo "Updating package lists..."
sudo apt update --fix-missing -y || sudo apt update --fix-missing -y
sudo apt upgrade -y

# Install Required Software (Apache2 & Squid)
install_package() {
    local pkg="$1"
    if ! dpkg -l | grep -q "^ii\s*$pkg"; then
        echo "Installing $pkg..."
        sudo apt install -y "$pkg" || (echo "ERROR: Failed to install $pkg!" && exit 1)
        sudo systemctl enable "$pkg"
        sudo systemctl start "$pkg"
        echo "$pkg installed successfully."
    else
        echo "$pkg is already installed."
    fi
}

install_package "apache2"
install_package "squid"

# Create Users and SSH Keys
USERS=("dennis" "aubrey" "captain" "snibbles" "brownie" "scooter" "sandy" "perrier" "cindy" "tiger" "yoda")
DENNIS_SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI student@generic-vm"

for user in "${USERS[@]}"; do
    if ! id "$user" &>/dev/null; then
        echo "Creating user: $user..."
        sudo useradd -m -s /bin/bash "$user"
    else
        echo "User $user already exists."
    fi

    HOME_DIR="/home/$user"
    SSH_DIR="$HOME_DIR/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"

    sudo mkdir -p "$SSH_DIR"
    sudo chmod 700 "$SSH_DIR"

    if [ ! -f "$SSH_DIR/id_rsa" ]; then
        sudo ssh-keygen -t rsa -N "" -f "$SSH_DIR/id_rsa"
    fi
    if [ ! -f "$SSH_DIR/id_ed25519" ]; then
        sudo ssh-keygen -t ed25519 -N "" -f "$SSH_DIR/id_ed25519"
    fi

    cat "$SSH_DIR/id_rsa.pub" "$SSH_DIR/id_ed25519.pub" | sudo tee "$AUTH_KEYS" > /dev/null
    sudo chmod 600 "$AUTH_KEYS"
    sudo chown -R "$user:$user" "$SSH_DIR"

    echo "SSH keys set up for $user."
done

# Ensure Dennis Has Sudo & Correct SSH Key
if id "dennis" &>/dev/null; then
    sudo usermod -aG sudo dennis
    sudo mkdir -p /home/dennis/.ssh
    echo "$DENNIS_SSH_KEY" | sudo tee /home/dennis/.ssh/authorized_keys > /dev/null
    sudo chown -R dennis:dennis /home/dennis/.ssh
    sudo chmod 700 /home/dennis/.ssh
    sudo chmod 600 /home/dennis/.ssh/authorized_keys
    echo "Dennis user updated with sudo privileges and SSH key."
fi

# Verify Services
echo "Verifying services..."
if systemctl is-active --quiet apache2; then
    echo "Apache2 is running."
else
    echo "Apache2 FAILED to start!"
fi

if systemctl is-active --quiet squid; then
    echo "Squid is running."
else
    echo "Squid FAILED to start!"
fi

echo "Configuration completed successfully."
