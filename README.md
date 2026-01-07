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

pip install -r requirements.txt


Usage

1. Decrypting Messages

Use decrypt_msg_and_attachment.py for payloads containing encrypted encryptedSymmetricKey and segmentEncryption fields.

Usage: python src/decrypt_msg_and_attachment.py <private_key.pem> [input_path]

private_key.pem: (Required) Path to your private key file.

input_path: (Optional) Path to a JSON file or a folder of JSON files. Defaults to data/inputs.

Examples:

# Process all files in data/inputs using a key in the keys folder
python src/decrypt_msg_and_attachment.py keys/private-client.pem

# Process a specific file
python src/decrypt_msg_and_attachment.py keys/private-client.pem data/inputs/specific_test.json


Output: Decrypted content is saved to data/outputs/decrypted_message/ and data/outputs/decrypted_attachment/.

2. Extracting Unencrypted Payloads

Use extract_msg_and_attachment.py for payloads that are plain Base64 encoded (no encryption).

Usage: python src/extract_msg_and_attachment.py [input_path]

input_path: (Optional) Path to a JSON file or a folder of JSON files. Defaults to data/inputs.

Examples:

# Process all files in data/inputs
python src/extract_msg_and_attachment.py

# Process a specific folder
python src/extract_msg_and_attachment.py data/other_test_data/


Output: Extracted content is saved to data/outputs/extracted_message/ and data/outputs/extracted_attachment/.