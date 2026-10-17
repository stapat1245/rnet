#!/usr/bin/env bash
set -euo pipefail

# Replace with your VPS public IP address
VPS_PUBLIC_IP="172.197.216.135"

sudo apt update
sudo apt install -y git curl build-essential pkg-config wireguard-tools

# Check that Rust and Cargo are installed
if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: Cargo is not installed."
    echo "Install Rust using https://rustup.rs/ and rerun this script."
    exit 1
fi

git clone https://github.com/stapat1245/rnet.git
cd rnet

if [[ ! -f Cargo.toml ]]; then
    echo "Error: Cargo.toml not found."
    exit 1
fi

cargo build --release -p mynet-cli

if [[ ! -f target/release/rnet ]]; then
    echo "Error: target/release/rnet was not created."
    echo "Check the package's binary name in Cargo.toml."
    exit 1
fi

# Install the executable
sudo install -m 755 target/release/rnet /usr/local/bin/rnet

# Create the configuration directory
mkdir -p "$HOME/.config/mynet"
chmod 700 "$HOME/.config/mynet"

cat > "$HOME/.config/mynet/discovery.toml" <<EOF
coordinator = "${VPS_PUBLIC_IP}:9993"
relay = "${VPS_PUBLIC_IP}:9994"
EOF

chmod 600 "$HOME/.config/mynet/discovery.toml"
echo "Installation completed."
echo "Configuration: $HOME/.config/mynet/discovery.toml"