# Operating-Systems-Lab4-code-samples
# Archive Extraction Tool

This project is an archive extraction tool written in C (`archextract.c`) that processes hex or `xxd`-style archive files and extracts their contents using a Python script (`unpack_data.py`). It supports multiple archive versions and processing methods like ZLIB, LZMA, and Fernet encryption.

It supports archive versions `0x01` and `0x02` (with potential for `0x03` with updates), handles little-endian and big-endian byte orders, and supports processing methods like `NONE`, `ZLIB`, `LZMA`, and `FERNET`. The tool creates output directories, logs events to `unpack.log`, and stores file metadata in `file_info.txt`. Verbosity levels can be adjusted with the `-v` flag for debugging.

To install, compile the C code using `gcc -o archextract archextract.c` and make sure `unpack_data.py` is in the same directory.

To run the program, use the following format:  
`./archextract -i <input_archive> [-o <output_dir>] [-v [0|1|2]]`

Here, `-i` specifies the input archive file (e.g., `archive_le.hex` or `archive_be_with_offsets2.txt`), `-o` optionally sets the output directory (default is `./unpacked`), and `-v` controls the verbosity level (`0` = quiet, `1` = normal, `2` = detailed).

The main files in the project are:  
• `archextract.c`: Main extraction logic  
• `unpack_data.py`: Handles decompression and decryption  
• `unpack.log`: Event and error logs  
• `file_info.txt`: Metadata about extracted files

Prerequisites include a C compiler (like `gcc`), Python 3 with `zlib`, `lzma`, and `cryptography` libraries, and an OS that supports `mkdir` and system-level commands.
