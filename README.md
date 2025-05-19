# Operating-Systems-Lab4-code-samples
### Updated README for Archive Extraction Tool

This project is an archive extraction tool written in C (`archextract.c`) that processes hex or xxd-style archive files and extracts their contents using a Python script (`unpack_data.py`). It supports multiple archive versions and processing methods like ZLIB, LZMA, and Fernet encryption.

It supports archive versions 0x01 and 0x02 (with potential for 0x03 with updates), handles little-endian and big-endian byte orders, and supports processing methods like NONE, ZLIB, LZMA, and FERNET. The tool creates output directories, logs events to `unpack.log`, and stores file metadata in `file_info.txt`. Verbosity levels can be adjusted with the `-v` flag for debugging.

---

### Prerequisites

To build and run this project, ensure the following are installed:

#### For the C Component (`archextract.c`):
- **C Compiler**: A C compiler like `gcc` is required to compile the program.
- **Libraries**:
  - `zlib`: For ZLIB decompression support (used indirectly via the Python script).
  - `liblzma`: For LZMA decompression support (used indirectly via the Python script).
  - No direct dependency on `libsodium` is required for the C code, as Fernet encryption is handled by the Python script.
- **System Headers**:
  - Standard C libraries: `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<stdint.h>`, `<sys/stat.h>`, `<sys/types.h>`, `<unistd.h>`, `<errno.h>`, `<ctype.h>`.
- **OS Support**: An operating system that supports `mkdir` and system-level commands (e.g., Linux, macOS, or a POSIX-compliant system).

#### For the Python Component (`unpack_data.py`):
- **Python 3**: Python 3.6 or later is required to run the script.
- **Python Libraries**:
  - `zlib`: For ZLIB decompression (standard library module, usually included with Python).
  - `lzma`: For LZMA decompression (standard library module, usually included with Python).
  - `cryptography`: For Fernet encryption/decryption. Install via:
    ```bash
    pip install cryptography
    ```
  - Standard Python libraries: `sys`, `base64`, `logging`, `os` (all included with Python).
- **Environment**: Ensure `unpack_data.py` is in the same directory as `archextract` or in the system PATH so the C program can call it using `system()`.

#### General Requirements:
- File system permissions to create directories and write files (e.g., for output directories, `unpack.log`, and `file_info.txt`).
- A terminal or command-line interface to execute the program.

---

### Installation

1. **Install Dependencies**:
   - On a Debian-based system (e.g., Ubuntu), install the required libraries:
     ```bash
     sudo apt update
     sudo apt install build-essential zlib1g-dev liblzma-dev python3 python3-pip
     pip3 install cryptography
     ```
   - On a Red Hat-based system (e.g., Fedora), use:
     ```bash
     sudo dnf install gcc zlib-devel xz-devel python3 python3-pip
     pip3 install cryptography
     ```
   - For macOS, use Homebrew:
     ```bash
     brew install gcc zlib xz python3
     pip3 install cryptography
     ```

2. **Compile the C Code**:
   Compile `archextract.c` using `gcc`. The `-lz` and `-llzma` flags are included for potential direct linking (though not used directly here since decompression is handled by Python):
   ```bash
   gcc -o archextract archextract.c -lz -llzma
   ```

3. **Ensure Python Script is Available**:
   - Place `unpack_data.py` in the same directory as the compiled `archextract` binary.
   - Verify Python 3 is accessible by running:
     ```bash
     python3 --version
     ```

---

### Usage

To run the program, use the following format:
```bash
./archextract -i <input_archive> [-o <output_dir>] [-v [0|1|2]]
```
- `-i <input_archive>`: Specifies the input archive file (e.g., `archive_le.hex` or `archive_be_with_offsets2.txt`).
- `-o <output_dir>`: Optionally sets the output directory (default is `./unpacked`).
- `-v [0|1|2]`: Controls the verbosity level:
  - `0`: Quiet (minimal output).
  - `1`: Normal (logs to console and file).
  - `2`: Detailed (includes command execution details).

#### Example:
```bash
./archextract -i archive_le.hex -o extracted_files -v 1
```

---

### Main Files in the Project

- **`archextract.c`**: Contains the main extraction logic, handling archive parsing, file extraction, and coordination with the Python script.
- **`unpack_data.py`**: Handles decompression (ZLIB, LZMA) and decryption (Fernet) of archive data chunks.
- **`unpack.log`**: Generated log file containing events and errors during extraction.
- **`file_info.txt`**: Generated metadata file listing extracted files with their sizes and processing methods.

---

### Notes

- The tool assumes the input archive is either a hex dump (`.hex`) or an xxd-style dump (`.txt`).
- Ensure the output directory has write permissions.
- If `cryptography` is not installed, Fernet decryption will fail, and the program will log an error.
- The C program dynamically allocates memory for the archive data, so ensure sufficient system memory for large archives.

This setup ensures robust archive extraction with support for multiple processing methods and detailed logging for debugging.
