#!/usr/bin/env python3
import json
import base64
import sys
import os
import getpass
import mimetypes

# Try to import cryptography
try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: This script requires the 'cryptography' library.")
    print("Please install it by running: pip3 install cryptography")
    sys.exit(1)

# --- CONFIGURATION ---
# Output paths relative to the project root (assuming script runs from root)
BASE_OUTPUT_DIR = os.path.join("data", "outputs")
OUTPUT_DIR_MSG = os.path.join(BASE_OUTPUT_DIR, "decrypted_message")
OUTPUT_DIR_ATT = os.path.join(BASE_OUTPUT_DIR, "decrypted_attachment")

def setup_directories():
    """Creates the output directories if they don't exist."""
    for d in [OUTPUT_DIR_MSG, OUTPUT_DIR_ATT]:
        if not os.path.exists(d):
            os.makedirs(d)
            print(f"[*] Created output directory: {d}")

def detect_extension(data):
    """
    Inspects the first few bytes (Magic Bytes) of the decrypted data
    to determine the actual file type.
    """
    if len(data) < 12:
        return None

    # --- Images ---
    if data.startswith(b'\xff\xd8\xff'): return '.jpg'
    if data.startswith(b'\x89PNG\r\n\x1a\n'): return '.png'
    if data.startswith(b'GIF87a') or data.startswith(b'GIF89a'): return '.gif'
    if data.startswith(b'BM'): return '.bmp'
    if data.startswith(b'II*\x00') or data.startswith(b'MM\x00*'): return '.tiff'
    if data.startswith(b'RIFF') and data[8:12] == b'WEBP': return '.webp'
        
    # --- Audio ---
    if data.startswith(b'caff'): return '.caf'
    if data.startswith(b'#!AMR'): return '.amr'
    if data.startswith(b'ID3') or data.startswith(b'\xff\xfb') or data.startswith(b'\xff\xf3'): return '.mp3'
    if data.startswith(b'RIFF') and data[8:12] == b'WAVE': return '.wav'
    if data.startswith(b'OggS'): return '.ogg'
    if data.startswith(b'fLaC'): return '.flac'

    # --- Video / ISO Base Media ---
    if data[4:8] == b'ftyp':
        major_brand = data[8:12]
        if major_brand == b'qt  ': return '.mov'
        if major_brand == b'M4A ': return '.m4a'
        if major_brand == b'M4V ': return '.m4v'
        if major_brand in [b'isom', b'mp41', b'mp42']: return '.mp4'
        return '.mp4' 

    # --- Documents / Archives ---
    if data.startswith(b'%PDF-'): return '.pdf'
    if data.startswith(b'PK\x03\x04'): return '.zip'
    if data.startswith(b'{\\rtf1'): return '.rtf'

    return None

def decrypt_aes_gcm(symmetric_key, ciphertext_b64, iv_b64, auth_tag_b64):
    """Helper to perform the AES-GCM decryption."""
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    auth_tag = base64.b64decode(auth_tag_b64)

    decryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.GCM(iv, auth_tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()

def process_double_base64(data):
    """Checks if the data is a Base64 string masquerading as binary and decodes it."""
    prefixes = [b'AAAAHGZ0', b'Y2Fm', b'IyFBT', b'/9j/', b'iVBOR', b'JVBER']
    
    if any(data.startswith(p) for p in prefixes):
        try:
            decoded = base64.b64decode(data)
            return decoded
        except Exception:
            pass 
    return data

def load_private_key(private_key_path):
    print(f"[*] Loading private key from: {private_key_path}")
    try:
        with open(private_key_path, "rb") as key_file:
            key_data = key_file.read()

        if key_data.strip().startswith(b"-----BEGIN"):
            password = None
            if b"ENCRYPTED" in key_data:
                print("    [?] Detected Encrypted PEM Key.")
                pwd_input = getpass.getpass("    [?] Enter PEM Key Password: ")
                password = pwd_input.encode()
            return serialization.load_pem_private_key(key_data, password=password, backend=default_backend())
        else:
            print("    [-] Error: File is not a PEM private key.")
            sys.exit(1)
    except Exception as e:
        print(f"Unexpected error loading key: {e}")
        sys.exit(1)

def process_payload(json_file_path, private_key):
    """Processes a single JSON file."""
    base_filename = os.path.splitext(os.path.basename(json_file_path))[0]
    print(f"\n[*] Processing file: {os.path.basename(json_file_path)}")

    # 1. Load JSON
    try:
        with open(json_file_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"    [-] Error loading JSON: {e}")
        return

    # 2. Decrypt Symmetric Key
    symmetric_key = None
    try:
        # --- ROBUST CHECKING START ---
        attributes = data.get("attributes")
        if not attributes:
            print("    [-] Skipping: Schema mismatch (Missing 'attributes' field).")
            return
        
        encryption_info = attributes.get("encryption")
        if not encryption_info:
            print("    [-] Skipping: File appears unencrypted (Missing 'encryption' field).")
            return
            
        enc_sym_key_b64 = encryption_info.get("encryptedSymmetricKey")
        if not enc_sym_key_b64:
             print("    [-] Skipping: No symmetric key found.")
             return
        # --- ROBUST CHECKING END ---

        enc_sym_key_bytes = base64.b64decode(enc_sym_key_b64)

        symmetric_key = private_key.decrypt(
            enc_sym_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"    [-] Failed to decrypt symmetric key: {e}")
        return

    payload = data.get("payload", {})

    # 3. Decrypt Message / Text Content
    target_obj = None
    content_key = None
    output_filename = f"{base_filename}_message.txt"

    if "message" in payload and isinstance(payload["message"], dict):
        target_obj = payload["message"]
        content_key = "message"
    elif "text" in payload and isinstance(payload["text"], dict):
        target_obj = payload["text"]
        content_key = "text"
        output_filename = f"{base_filename}_text.txt"

    if target_obj:
        try:
            if content_key not in target_obj:
                if "text" in target_obj: content_key = "text"
                elif "message" in target_obj: content_key = "message"
            
            if content_key in target_obj and "segmentEncryption" in target_obj:
                c_text = target_obj[content_key]
                iv = target_obj["segmentEncryption"]["initializationVector"]
                tag = target_obj["segmentEncryption"]["authTag"]
                
                decrypted_bytes = decrypt_aes_gcm(symmetric_key, c_text, iv, tag)
                decrypted_text = decrypted_bytes.decode('utf-8')
                
                out_path = os.path.join(OUTPUT_DIR_MSG, output_filename)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(decrypted_text)
                
                print(f"    [+] Decrypted text: {output_filename}")
        except Exception as e:
            print(f"    [-] Failed to decrypt text content: {e}")

    # 4. Decrypt Attachments
    attachments = []
    if target_obj:
        attachments = target_obj.get("attachments", [])
    
    if attachments:
        print(f"    [+] Found {len(attachments)} attachment(s).")
        for i, att in enumerate(attachments):
            try:
                c_text = att["data"]
                iv = att["segmentEncryption"]["initializationVector"]
                tag = att["segmentEncryption"]["authTag"]
                
                decrypted_bytes = decrypt_aes_gcm(symmetric_key, c_text, iv, tag)
                decrypted_bytes = process_double_base64(decrypted_bytes)
                
                real_ext = detect_extension(decrypted_bytes)
                
                raw_name = att.get("fileName", "").strip()
                base_att_name = ""
                original_ext = ""
                if raw_name:
                    base_att_name, original_ext = os.path.splitext(raw_name)

                if not real_ext:
                    if original_ext:
                        real_ext = original_ext
                    else:
                        mime_type = att.get("mimeType", "application/octet-stream")
                        if mime_type != "application/octet-stream":
                            real_ext = mimetypes.guess_extension(mime_type)
                
                if not real_ext: real_ext = '.dat'
                
                if base_att_name:
                    fname = f"{base_filename}_{base_att_name}{real_ext}"
                else:
                    fname = f"{base_filename}_attachment_{i+1}{real_ext}"
                
                out_path = os.path.join(OUTPUT_DIR_ATT, fname)
                with open(out_path, "wb") as f:
                    f.write(decrypted_bytes)
                print(f"        [+] Saved: {fname}")
                
            except Exception as e:
                print(f"        [-] Error processing attachment {i+1}: {e}")

def main():
    default_input_dir = os.path.join("data", "inputs")
    input_path = None
    key_path = None

    # Parse arguments
    args = sys.argv[1:]
    
    # Heuristic: Find argument ending in .pem -> Key Path
    for arg in args:
        if arg.endswith('.pem'):
            key_path = arg
            break
            
    # Heuristic: Find argument NOT ending in .pem -> Input Path
    for arg in args:
        if arg != key_path:
            input_path = arg
            break
            
    # Defaults
    if not input_path:
        input_path = default_input_dir

    if not key_path:
        print("\nUsage: python src/decrypt_msg_and_attachment.py <private_key.pem> [input_path]")
        print(f"   [input_path] defaults to '{default_input_dir}' if omitted.")
        print("   <private_key.pem> is required.")
        sys.exit(1)

    if not os.path.exists(input_path):
        print(f"Error: Input path not found: {input_path}")
        sys.exit(1)
        
    if not os.path.exists(key_path):
        print(f"Error: Key file not found: {key_path}")
        sys.exit(1)

    setup_directories()
    
    private_key = load_private_key(key_path)

    files_to_process = []
    if os.path.isfile(input_path):
        files_to_process.append(input_path)
    elif os.path.isdir(input_path):
        for f in os.listdir(input_path):
            if f.lower().endswith(".json"):
                files_to_process.append(os.path.join(input_path, f))
        files_to_process.sort() 
    
    if not files_to_process:
        print(f"No JSON files found in {input_path}")
        sys.exit(0)

    print(f"[*] Found {len(files_to_process)} file(s) to process.")
    
    for json_file in files_to_process:
        process_payload(json_file, private_key)

    print("\n" + "="*40)
    print("Batch processing complete.")

if __name__ == "__main__":
    main()