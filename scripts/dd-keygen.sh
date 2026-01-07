#!/bin/bash

# Configuration
KEY_FILENAME="temp_rsa_key"
COMMENT="test-key-$(date +%s)"

echo "Generating 2048-bit RSA key pair..."

# Generate the key pair
# -t rsa: Specifies RSA type
# -b 2048: Specifies 2048 bit length
# -f: Output filename
# -N "": Sets an empty passphrase (no password)
# -C: Adds a comment
# -q: Silence progress output
ssh-keygen -t rsa -b 2048 -f "$KEY_FILENAME" -N "" -C "$COMMENT" -q

# Display Public Key
echo ""
echo "============================================"
echo "               PUBLIC KEY                   "
echo "============================================"
ssh-keygen -e -m PKCS8 -f "${KEY_FILENAME}.pub"

# Display Private Key
echo ""
echo "============================================"
echo "               PRIVATE KEY                  "
echo "============================================"
cat "${KEY_FILENAME}"
echo "============================================"
echo ""

# Cleanup
rm "${KEY_FILENAME}" "${KEY_FILENAME}.pub"
echo "Temporary key files removed."

