#!/usr/bin/env bash
set -euo pipefail

# Replace with your VPS public IP address
VPS_PUBLIC_IP="172.197.216.135"


RCHAT_REPO="https://github.com/stapat1245/rchat.git"

sudo apt update
sudo apt install -y git curl build-essential pkg-config wireguard-tools

# Check that Rust and Cargo are installed
if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: Cargo is not installed."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    . "$HOME/.cargo/env"
fi

WORKDIR="$(pwd)"

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
echo "rnet installation completed."
echo "Configuration: $HOME/.config/mynet/discovery.toml"


# Decide whether to also install rchat:
# honor RNET_WITH_RCHAT=1/0 (yes/no) for non-interactive installs

want_rchat=""
if [[ -n "${RNET_WITH_RCHAT:-}" ]]; then
    case "${RNET_WITH_RCHAT}" in
        1|y|Y|yes|YES|true|TRUE) want_rchat="yes" ;;
        *) want_rchat="no" ;;
    esac
elif [[ -r /dev/tty ]]; then
    printf 'Also install rchat (P2P terminal chat over the overlay)? [Y/n] ' > /dev/tty
    read -r ans < /dev/tty || ans=""
    case "${ans}" in
        n|N|no|NO) want_rchat="no" ;;
        *) want_rchat="yes" ;;
    esac
else
    want_rchat="no"
fi

if [[ "${want_rchat}" == "yes" ]]; then
    echo "Installing rchat from ${RCHAT_REPO} ..."
    cd "$WORKDIR"
    rm -rf rchat
    if git clone "${RCHAT_REPO}" rchat; then
        cd rchat
        cargo build --release
        if [[ -f target/release/rchat ]]; then
            sudo install -m 755 target/release/rchat /usr/local/bin/rchat
            echo "rchat installation completed."
            echo "Run it after connecting the overlay:  rchat"
        else
            echo "Warning: rchat build did not produce target/release/rchat; skipping."
        fi
    else
        echo "Warning: could not clone ${RCHAT_REPO}; skipping rchat."
    fi
else
    echo "Skipping rchat. To add it later:  RNET_WITH_RCHAT=1 bash install.sh"
fi
