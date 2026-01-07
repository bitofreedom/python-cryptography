Python Cryptography Message Processor

This project provides tools to decrypt and extract payloads from JSON message data. It supports both RSA-OAEP/AES-GCM encrypted payloads and unencrypted base64 encoded payloads.

Project Structure

src/: Contains the main python scripts.

data/inputs/: Place your input JSON files here.

data/outputs/: Generated text and media files will appear here.

keys/: Place your private RSA keys (.pem) here.

Setup

Create a Virtual Environment:

python3 -m venv venv
source venv/bin/activate


Install Dependencies:

pip install cryptography


Usage

1. Decrypting Messages

Use decrypt_msg_and_attachment.py for payloads containing encrypted encryptedSymmetricKey and segmentEncryption fields.

# Run on a single file
python src/decrypt_msg_and_attachment.py data/inputs/encrypted_file.json keys/private_key.pem

# Run on a directory of files
python src/decrypt_msg_and_attachment.py data/inputs/ keys/private_key.pem


Output: Decrypted content is saved to data/outputs/decrypted_message/ and data/outputs/decrypted_attachment/.

2. Extracting Unencrypted Payloads

Use extract_msg_and_attachment.py for payloads that are plain Base64 encoded (no encryption).

# Run on a single file
python src/extract_msg_and_attachment.py data/inputs/unencrypted_file.json

# Run on a directory of files
python src/extract_msg_and_attachment.py data/inputs/


Output: Extracted content is saved to data/outputs/extracted_message/ and data/outputs/extracted_attachment/.