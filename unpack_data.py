import sys
import zlib
import lzma
from cryptography.fernet import Fernet
import base64
import logging
import os

# Configure logging with custom format
logging.basicConfig(
    filename='unpack.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

# Global verbosity setting
verbosity = 1

# Log a message to file and console if verbose
def emit_log(message):
    logging.info(message)
    if verbosity >= 1:
        print(message)

# Log an error to file and stderr
def emit_error(message):
    logging.error(message)
    print(f"Error: {message}", file=sys.stderr)

# Validate Fernet key length
def verify_key_format(key):
    try:
        decoded = base64.urlsafe_b64decode(key)
        valid_lengths = {16, 24, 32}
        return len(decoded) in valid_lengths
    except Exception:
        return False

# Process data with no transformation
def transform_none(data, expected_size):
    if len(data) != expected_size:
        emit_error("Size mismatch in raw data")
        return None
    return data

# Decompress data using zlib
def transform_zlib(data, expected_size):
    try:
        result = zlib.decompress(data)
        if len(result) != expected_size:
            emit_error("Zlib output size incorrect")
            return None
        return result
    except zlib.error as e:
        emit_error(f"Zlib failure: {e}")
        return None

# Decompress data using LZMA
def transform_lzma(data, expected_size):
    try:
        result = lzma.decompress(data)
        if len(result) != expected_size:
            emit_error("LZMA output size incorrect")
            return None
        return result
    except lzma.LZMAError as e:
        emit_error(f"LZMA failure: {e}")
        return None

# Decrypt data using Fernet
def transform_fernet(data, expected_size):
    if len(data) < 44:
        emit_error("Insufficient data for Fernet key")
        return None
    key = data[:44]
    if not verify_key_format(key):
        emit_error("Malformed Fernet key")
        return None
    try:
        cipher = Fernet(key)
        result = cipher.decrypt(data[44:])
        if len(result) != expected_size:
            emit_error("Fernet output size incorrect")
            return None
        emit_log(f"Decrypted using key: {key.decode()}")
        return result
    except Exception as e:
        emit_error(f"Fernet decryption error: {e}")
        return None

# Mapping of method IDs to processing functions
PROCESS_MAP = {
    0: transform_none,
    1: transform_zlib,
    2: transform_lzma,
    3: transform_fernet
}

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 unpack_data.py <method> <input> <output> <size>", file=sys.stderr)
        sys.exit(1)

    method_id = int(sys.argv[1])
    input_file = sys.argv[2]
    output_file = sys.argv[3]
    expected_size = int(sys.argv[4])

    # Read input data
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except Exception as e:
        emit_error(f"Cannot read input file: {e}")
        sys.exit(1)

    # Select processing function
    processor = PROCESS_MAP.get(method_id)
    if not processor:
        emit_error("Unknown processing method")
        sys.exit(1)

    # Process data
    result = processor(data, expected_size)
    if result is None:
        sys.exit(1)

    # Ensure output directory exists
    try:
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
    except Exception as e:
        emit_error(f"Cannot create output directory: {e}")
        sys.exit(1)

    # Write output data
    try:
        with open(output_file, 'wb') as f:
            f.write(result)
    except Exception as e:
        emit_error(f"Cannot write to output file {output_file}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
