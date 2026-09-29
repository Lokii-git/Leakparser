#!/bin/bash

# Path to your leakparser script
SCRIPT_PATH="/opt/leakparser/leakparser.py"
LINK_PATH="/usr/local/bin/leakparser"

# Ensure it's executable
chmod +x "$SCRIPT_PATH"

# Create the symlink
if [ -L "$LINK_PATH" ] || [ -e "$LINK_PATH" ]; then
    echo "[!] A file or link already exists at $LINK_PATH"
    echo "    You can remove it with: sudo rm $LINK_PATH"
else
    sudo ln -s "$SCRIPT_PATH" "$LINK_PATH"
    echo "[+] Symlink created: You can now run 'leakparser' from anywhere."
fi
