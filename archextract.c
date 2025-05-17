#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

// Constants for archive format
#define MAX_PATH_SIZE 512  // Increased to handle longer paths
#define MAX_LINE_SIZE 1024
#define ARCH_SIGNATURE 0x41524348 // "ARCH"
#define UNPACK_LOG "unpack.log"
#define INFO_FILE "file_info.txt"

// Enums for processing types and byte order
typedef enum { NONE_PROC = 0x00, ZLIB_PROC = 0x01, LZMA_PROC = 0x02, FERNET_PROC = 0x03 } ProcMethod;
typedef enum { BYTE_LITTLE, BYTE_BIG } ByteOrder;

// Global file pointers and verbosity level
static FILE *event_log = NULL;
static FILE *info_log = NULL;
static int trace_level = 0;

// Structure to track processed files
typedef struct {
    char filename[MAX_PATH_SIZE];
    int processed;
} ProcessedFile;
static ProcessedFile processed_list[100]; // Max 100 unique files
static int processed_count = 0;

// Log an event to file and optionally to console
void record_event(const char *event) {
    fprintf(event_log, "%s\n", event);
    if (trace_level >= 1) {
        printf("%s\n", event);
    }
}

// Log an error to file and stderr
void record_failure(const char *error) {
    fprintf(event_log, "FAIL: %s\n", error);
    fprintf(stderr, "FAIL: %s\n", error);
}

// Parse 32-bit integer with specified byte order
uint32_t decode_uint32(const uint8_t *data, ByteOrder order) {
    uint32_t result = 0;
    if (order == BYTE_LITTLE) {
        for (int i = 0; i < 4; i++) {
            result |= ((uint32_t)data[i]) << (i * 8);
        }
    } else {
        for (int i = 0; i < 4; i++) {
            result |= ((uint32_t)data[3 - i]) << (i * 8);
        }
    }
    return result;
}

// Parse 64-bit integer with specified byte order
uint64_t decode_uint64(const uint8_t *data, ByteOrder order) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= ((uint64_t)data[order == BYTE_LITTLE ? i : 7 - i]) << (i * 8);
    }
    return result;
}

// Check if file is a hex dump
int check_hex_format(const char *path) {
    const char *ext = strrchr(path, '.');
    return ext && strcmp(ext, ".hex") == 0;
}

// Check if file is an xxd-style dump
int check_xxd_format(const char *path) {
    const char *ext = strrchr(path, '.');
    return ext && strcmp(ext, ".txt") == 0;
}

// Parse a single line of hex data
int parse_hex_data(FILE *input, uint8_t *buffer, size_t *length, int xxd_format) {
    char line[MAX_LINE_SIZE];
    if (!fgets(line, MAX_LINE_SIZE, input)) {
        return 0;
    }

    *length = 0;
    if (xxd_format) {
        char *hex_start = strchr(line, ':');
        if (!hex_start) {
            record_failure("Invalid xxd line format");
            return 0;
        }
        hex_start++;
        while (*hex_start == ' ') hex_start++;
        for (; isxdigit(hex_start[0]) && isxdigit(hex_start[1]); hex_start += 2) {
            sscanf(hex_start, "%2hhx", &buffer[*length]);
            (*length)++;
            if (hex_start[2] == ' ') hex_start++;
        }
    } else {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') len--;
        if (len % 2 != 0) {
            record_failure("Malformed hex line");
            return 0;
        }
        *length = len / 2;
        for (size_t i = 0; i < *length; i++) {
            sscanf(&line[i * 2], "%2hhx", &buffer[i]);
        }
    }
    return 1;
}

// Create necessary directories for output path
int setup_directories(const char *path) {
    char temp_path[MAX_PATH_SIZE];
    strncpy(temp_path, path, MAX_PATH_SIZE - 1);
    temp_path[MAX_PATH_SIZE - 1] = '\0';
    for (char *p = temp_path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp_path, 0755) && errno != EEXIST) {
                record_failure("Directory creation failed");
                return 0;
            }
            *p = '/';
        }
    }
    return 1;
}

// Write temporary file for processing with size validation
int write_temp_file(const uint8_t *data, size_t size, const char *filename) {
    FILE *temp = fopen(filename, "wb");
    if (!temp) {
        record_failure("Cannot create temporary file");
        return 0;
    }
    size_t written = fwrite(data, 1, size, temp);
    fclose(temp);
    if (written != size) {
        record_failure("Incomplete write to temporary file");
        return 0;
    }
    return 1;
}

// Check if file has been processed
int is_file_processed(const char *filename) {
    for (int i = 0; i < processed_count; i++) {
        if (strcmp(processed_list[i].filename, filename) == 0) {
            return 1;
        }
    }
    return 0;
}

// Add file to processed list
void mark_file_processed(const char *filename) {
    if (!is_file_processed(filename) && processed_count < 100) {
        strncpy(processed_list[processed_count].filename, filename, MAX_PATH_SIZE - 1);
        processed_list[processed_count].filename[MAX_PATH_SIZE - 1] = '\0';
        processed_list[processed_count].processed = 1;
        processed_count++;
    }
}

// Extract a single file entry with path length check, supporting multiple versions
int extract_entry(uint8_t *archive, size_t *index, size_t archive_size, const char *dest_dir, ByteOrder order, uint8_t version) {
    if (*index + 13 > archive_size) {
        record_failure("Truncated entry header");
        return 0;
    }

    uint32_t name_len = decode_uint32(&archive[*index], order);
    *index += 4;
    if (*index + name_len + 17 > archive_size) {
        record_failure("Incomplete entry data");
        return 0;
    }

    char filepath[MAX_PATH_SIZE];
    strncpy(filepath, (char *)&archive[*index], name_len);
    filepath[name_len] = '\0';
    *index += name_len;

    uint64_t raw_size = decode_uint64(&archive[*index], order);
    *index += 8;
    uint64_t proc_size = decode_uint64(&archive[*index], order);
    *index += 8;
    ProcMethod method = archive[*index];
    *index += 1;

    if (*index + proc_size > archive_size) {
        record_failure("Entry data exceeds archive bounds");
        return 0;
    }

    // Skip if already processed
    if (is_file_processed(filepath)) {
        *index += proc_size; // Skip duplicate entry data
        return 1;
    }

    const char *method_name = "unknown";
    switch (method) {
        case NONE_PROC: method_name = "none"; break;
        case ZLIB_PROC: method_name = "zlib"; break;
        case LZMA_PROC: method_name = "lzma"; break;
        case FERNET_PROC: method_name = "fernet"; break;
        default:
            record_failure("Unknown processing method");
            return 0;
    }

    fprintf(info_log, "%s\t%llu\t%llu\t%s\n", filepath, raw_size, proc_size, method_name);
    char log_msg[128];
    snprintf(log_msg, sizeof(log_msg), "Handling %s: proc_method=%s, raw_size=%llu, comp_size=%llu", filepath, method_name, raw_size, proc_size);
    record_event(log_msg);

    char full_path[MAX_PATH_SIZE];
    int path_len = snprintf(full_path, MAX_PATH_SIZE, "%s/%s", dest_dir, filepath);
    if (path_len >= MAX_PATH_SIZE || path_len < 0) {
        record_failure("Path too long or invalid");
        return 0;
    }
    if (!setup_directories(full_path)) {
        return 0;
    }

    // For version 0x02, handle Fernet encryption key if present
    size_t data_offset = 0;
    if (version == 0x02 && method == FERNET_PROC) {
        if (proc_size < 44) {
            record_failure("Fernet data too short for key");
            return 0;
        }
        data_offset = 44; // Skip the 44-byte encryption key
    }

    if (!write_temp_file(&archive[*index], proc_size, "temp_chunk.bin")) {
        return 0;
    }
    *index += proc_size;

    char command[512];
    snprintf(command, sizeof(command), "python3 unpack_data.py %d temp_chunk.bin %s %llu", method, full_path, raw_size);
    if (trace_level >= 2) {
        printf("Command: %s\n", command);
    }
    if (system(command) != 0) {
        record_failure("Processing command failed");
        unlink("temp_chunk.bin");
        return 0;
    }
    unlink("temp_chunk.bin");

    mark_file_processed(filepath);
    return 1;
}

int main(int argc, char *argv[]) {
    char *input_path = NULL;
    char *output_path = "./unpacked";
    trace_level = 0;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) {
            input_path = argv[++i];
        } else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
            output_path = argv[++i];
        } else if (!strcmp(argv[i], "-v") && i + 1 < argc) {
            trace_level = isdigit(argv[i + 1][0]) ? atoi(argv[++i]) : 1;
        }
    }

    if (!input_path) {
        fprintf(stderr, "Usage: %s -i <input> [-o <output_dir>] [-v [0|1|2]]\n", argv[0]);
        return 1;
    }

    event_log = fopen(UNPACK_LOG, "w");
    if (!event_log) {
        fprintf(stderr, "Cannot open log file\n");
        return 1;
    }

    if (mkdir(output_path, 0755) && errno != EEXIST) {
        record_failure("Unable to create output directory");
        fclose(event_log);
        return 1;
    }

    char info_path[MAX_PATH_SIZE];
    snprintf(info_path, MAX_PATH_SIZE, "%s/%s", output_path, INFO_FILE);
    info_log = fopen(info_path, "w");
    if (!info_log) {
        record_failure("Cannot open info file");
        fclose(event_log);
        return 1;
    }

    FILE *input = fopen(input_path, "r");
    if (!input) {
        record_failure("Cannot read input archive");
        fclose(event_log);
        fclose(info_log);
        return 1;
    }

    int is_hex = check_hex_format(input_path);
    int is_xxd = check_xxd_format(input_path);
    if (!is_hex && !is_xxd) {
        record_failure("Unsupported archive format");
        fclose(input);
        fclose(event_log);
        fclose(info_log);
        return 1;
    }

    // Initialize archive buffer
    size_t capacity = 1024;
    uint8_t *archive_data = malloc(capacity);
    if (!archive_data) {
        record_failure("Failed to allocate memory");
        fclose(input);
        fclose(event_log);
        fclose(info_log);
        return 1;
    }
    size_t data_size = 0;

    uint8_t buffer[256];
    size_t buffer_len;
    for (; parse_hex_data(input, buffer, &buffer_len, is_xxd); data_size += buffer_len) {
        if (data_size + buffer_len > capacity) {
            capacity *= 2;
            uint8_t *new_data = realloc(archive_data, capacity);
            if (!new_data) {
                record_failure("Memory expansion failed");
                free(archive_data);
                fclose(input);
                fclose(event_log);
                fclose(info_log);
                return 1;
            }
            archive_data = new_data;
        }
        memcpy(&archive_data[data_size], buffer, buffer_len);
    }
    fclose(input);

    if (data_size < 5) {
        record_failure("Archive too small");
        free(archive_data);
        fclose(event_log);
        fclose(info_log);
        return 1;
    }

    // Validate archive header
    uint32_t signature = decode_uint32(archive_data, BYTE_BIG);
    ByteOrder order = BYTE_BIG;
    if (signature != ARCH_SIGNATURE) {
        signature = decode_uint32(archive_data, BYTE_LITTLE);
        if (signature != ARCH_SIGNATURE) {
            record_failure("Invalid archive signature");
            free(archive_data);
            fclose(event_log);
            fclose(info_log);
            return 1;
        }
        order = BYTE_LITTLE;
    }

    // Read the version
    uint8_t version = archive_data[4];
    if (version != 0x01 && version != 0x02) {
        record_failure("Unsupported archive version");
        free(archive_data);
        fclose(event_log);
        fclose(info_log);
        return 1;
    }

    char version_msg[64];
    snprintf(version_msg, sizeof(version_msg), "Detected archive version: 0x%02x", version);
    record_event(version_msg);

    // Process archive entries
    size_t position = 5;
    for (; position < data_size;) {
        if (!extract_entry(archive_data, &position, data_size, output_path, order, version)) {
            record_event("Continuing after entry error");
        }
    }

    free(archive_data);
    fclose(event_log);
    fclose(info_log);
    return 0;
}
