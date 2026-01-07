#!/usr/bin/env python3
import json
import base64
import sys
import os
import mimetypes

# --- CONFIGURATION ---
OUTPUT_DIR_MSG = "extracted_message"
OUTPUT_DIR_ATT = "extracted_attachment"

def setup_directories():
    """Creates the output directories if they don't exist."""
    for d in [OUTPUT_DIR_MSG, OUTPUT_DIR_ATT]:
        if not os.path.exists(d):
            os.makedirs(d)
            print(f"[*] Created output directory: {d}")

def detect_extension(data):
    """
    Inspects the first few bytes (Magic Bytes) of the data
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

def process_double_base64(data):
    """
    Checks if the binary data is actually a Base64 string masquerading as binary 
    and decodes it again if necessary.
    """
    # Common headers in Base64:
    # M4A (AAAA), CAF (Y2Fm), AMR (IyFB), JPG (/9j/), PNG (iVBOR), PDF (JVBER)
    prefixes = [b'AAAAHGZ0', b'Y2Fm', b'IyFBT', b'/9j/', b'iVBOR', b'JVBER']
    
    if any(data.startswith(p) for p in prefixes):
        # print("        [!] Detected Double-Base64 encoding. Decoding again...")
        try:
            decoded = base64.b64decode(data)
            # print("        [+] Successfully decoded base64 content.")
            return decoded
        except Exception:
            pass # Return original data if decode fails
    return data

def process_payload(json_file_path):
    """Processes a single unencrypted JSON file."""
    base_filename = os.path.splitext(os.path.basename(json_file_path))[0]
    print(f"\n[*] Processing file: {os.path.basename(json_file_path)}")

    # 1. Load JSON
    try:
        with open(json_file_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"    [-] Error loading JSON: {e}")
        return

    payload = data.get("payload", {})

    # 2. Extract Message / Text Content
    target_obj = None
    content_key = None
    output_filename = f"{base_filename}_message.txt"

    # Identify where the message content lives
    if "message" in payload and isinstance(payload["message"], dict):
        target_obj = payload["message"]
        content_key = "message"
    elif "text" in payload and isinstance(payload["text"], dict):
        target_obj = payload["text"]
        content_key = "text"
        output_filename = f"{base_filename}_text.txt"

    if target_obj:
        try:
            # Fallback check if keys are swapped
            if content_key not in target_obj:
                if "text" in target_obj: content_key = "text"
                elif "message" in target_obj: content_key = "message"
            
            if content_key in target_obj:
                message_content = target_obj[content_key]
                
                # Unlike encrypted payloads, this is likely plain text.
                # However, if it happens to be bytes/None, handle gracefully.
                if message_content:
                    out_path = os.path.join(OUTPUT_DIR_MSG, output_filename)
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(str(message_content))
                    
                    print(f"    [+] Extracted text: {output_filename}")
                else:
                    print("    [-] Message content was empty.")
            else:
                pass 
        except Exception as e:
            print(f"    [-] Failed to extract text content: {e}")

    # 3. Extract Attachments
    attachments = []
    if target_obj:
        attachments = target_obj.get("attachments", [])
    
    if attachments:
        print(f"    [+] Found {len(attachments)} attachment(s).")
        for i, att in enumerate(attachments):
            try:
                # In JSON, binary data is ALWAYS Base64 encoded.
                # So we must decode it at least once.
                raw_b64 = att.get("data")
                if not raw_b64:
                    print(f"        [-] Attachment {i+1} has no data field.")
                    continue

                # 1. Primary Decode (Standard JSON transport)
                file_bytes = base64.b64decode(raw_b64)
                
                # 2. Check for Double-Encoding (Payload specific issue)
                file_bytes = process_double_base64(file_bytes)
                
                # 3. Detect Extension
                real_ext = detect_extension(file_bytes)
                
                raw_name = att.get("fileName", "").strip()
                base_att_name = ""
                original_ext = ""
                if raw_name:
                    base_att_name, original_ext = os.path.splitext(raw_name)

                # If Magic Bytes failed, try existing filename extension
                if not real_ext:
                    if original_ext:
                        real_ext = original_ext
                    else:
                        # If no original extension, try mimeType
                        mime_type = att.get("mimeType", "application/octet-stream")
                        if mime_type != "application/octet-stream":
                            real_ext = mimetypes.guess_extension(mime_type)
                
                # Final fallback
                if not real_ext:
                    real_ext = '.dat'
                
                # Construct Filename
                if base_att_name:
                    fname = f"{base_filename}_{base_att_name}{real_ext}"
                else:
                    fname = f"{base_filename}_attachment_{i+1}{real_ext}"
                
                out_path = os.path.join(OUTPUT_DIR_ATT, fname)
                with open(out_path, "wb") as f:
                    f.write(file_bytes)
                print(f"        [+] Saved: {fname}")
                
            except Exception as e:
                print(f"        [-] Error processing attachment {i+1}: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_unencrypted_payload.py <input_path>")
        print("   <input_path> can be a single .json file OR a directory containing .json files.")
        sys.exit(1)

    input_path = sys.argv[1]

    if not os.path.exists(input_path):
        print(f"Error: Path not found: {input_path}")
        sys.exit(1)

    setup_directories()
    
    # Determine files to process
    files_to_process = []
    if os.path.isfile(input_path):
        files_to_process.append(input_path)
    elif os.path.isdir(input_path):
        for f in os.listdir(input_path):
            if f.lower().endswith(".json"):
                files_to_process.append(os.path.join(input_path, f))
        files_to_process.sort() # Ensure consistent order
    
    if not files_to_process:
        print("No JSON files found to process.")
        sys.exit(0)

    print(f"[*] Found {len(files_to_process)} file(s) to process.")
    
    for json_file in files_to_process:
        process_payload(json_file)

    print("\n" + "="*40)
    print("Batch processing complete.")

if __name__ == "__main__":
    main()
