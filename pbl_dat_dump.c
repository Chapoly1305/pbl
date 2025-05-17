#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pbl.h"

void print_help() {
    printf("Usage: pbl_dat_dump [options] <filename>\n");
    printf("Options:\n");
    printf("  -k             Treat file as a PBL key file\n");
    printf("  -i             Treat file as a PBL ISAM file\n");
    printf("  -h             Show this help\n");
}

void dump_keyfile(const char* filename) {
    pblKeyFile_t* kf;
    unsigned char key[PBLKEYLENGTH];
    size_t keylen = PBLKEYLENGTH;
    unsigned char* data;
    long datalen;
    
    kf = pblKfOpen(filename, 0, NULL);
    if (!kf) {
        fprintf(stderr, "Error opening key file: %s\n", pbl_errstr);
        return;
    }
    
    printf("# PBL Key File: %s\n", filename);
    printf("# %-20s | %-8s | %s\n", "Key", "Data Len", "Data (first 32 bytes)");
    printf("# %s\n", "------------------------------------------------------------");
    
    datalen = pblKfFirst(kf, key, &keylen);
    if (datalen < 0) {
        if (pbl_errno == PBL_ERROR_NOT_FOUND) {
            printf("# File is empty\n");
        } else {
            fprintf(stderr, "Error getting first record: %s\n", pbl_errstr);
        }
        pblKfClose(kf);
        return;
    }
    
    do {
        int i;
        
        // Print the key (up to 20 chars)
        printf("  ");
        for (i = 0; i < keylen && i < 20; i++) {
            if (key[i] >= 32 && key[i] <= 126) {
                printf("%c", key[i]);
            } else {
                printf("\\x%02x", key[i]);
            }
        }
        
        // Pad with spaces to align columns
        for (; i < 20; i++) {
            printf(" ");
        }
        
        printf(" | %-8ld | ", datalen);
        
        // Read and print data
        if (datalen > 0) {
            data = malloc(datalen);
            if (!data) {
                fprintf(stderr, "Memory allocation error\n");
                break;
            }
            
            if (pblKfRead(kf, data, datalen) != datalen) {
                fprintf(stderr, "Error reading data: %s\n", pbl_errstr);
                free(data);
                break;
            }
            
            // Print the first 32 bytes of data
            for (i = 0; i < datalen && i < 32; i++) {
                if (data[i] >= 32 && data[i] <= 126) {
                    printf("%c", data[i]);
                } else {
                    printf("\\x%02x", data[i]);
                }
            }
            if (datalen > 32) {
                printf("...");
            }
            
            free(data);
        }
        
        printf("\n");
        
        // Get ready for next record
        keylen = PBLKEYLENGTH;
    } while ((datalen = pblKfNext(kf, key, &keylen)) >= 0);
    
    if (pbl_errno != PBL_ERROR_NOT_FOUND) {
        fprintf(stderr, "Error during iteration: %s\n", pbl_errstr);
    }
    
    pblKfClose(kf);
}

void dump_isamfile(const char* filename) {
    pblIsamFile_t* isam;
    char* keyfilenames[1] = {(char*)"index0"};  // Default index file name
    int keydup[1] = {1};  // Allow duplicate keys
    unsigned char key[PBLKEYLENGTH];
    unsigned char* data;
    long datalen;
    
    isam = pblIsamOpen(filename, 0, NULL, 1, keyfilenames, keydup);
    if (!isam) {
        fprintf(stderr, "Error opening ISAM file: %s\n", pbl_errstr);
        return;
    }
    
    printf("# PBL ISAM File: %s\n", filename);
    printf("# %-20s | %-8s | %s\n", "Key (Index 0)", "Data Len", "Data (first 32 bytes)");
    printf("# %s\n", "------------------------------------------------------------");
    
    if (pblIsamGet(isam, PBLFIRST, 0, key) < 0) {
        if (pbl_errno == PBL_ERROR_NOT_FOUND) {
            printf("# File is empty\n");
        } else {
            fprintf(stderr, "Error getting first record: %s\n", pbl_errstr);
        }
        pblIsamClose(isam);
        return;
    }
    
    do {
        int i;
        
        // Read the key for index 0
        if (pblIsamReadKey(isam, 0, key) < 0) {
            fprintf(stderr, "Error reading key: %s\n", pbl_errstr);
            continue;
        }
        
        // Print the key (up to 20 chars)
        printf("  ");
        for (i = 0; i < 20; i++) {
            if (key[i] >= 32 && key[i] <= 126) {
                printf("%c", key[i]);
            } else if (key[i] == 0) {
                break;  // Stop at null terminator
            } else {
                printf("\\x%02x", key[i]);
            }
        }
        
        // Pad with spaces to align columns
        for (; i < 20; i++) {
            printf(" ");
        }
        
        // Get data length
        datalen = pblIsamReadDatalen(isam);
        if (datalen < 0) {
            fprintf(stderr, "Error getting data length: %s\n", pbl_errstr);
            continue;
        }
        
        printf(" | %-8ld | ", datalen);
        
        // Read and print data
        if (datalen > 0) {
            data = malloc(datalen);
            if (!data) {
                fprintf(stderr, "Memory allocation error\n");
                break;
            }
            
            if (pblIsamReadData(isam, data, datalen) != datalen) {
                fprintf(stderr, "Error reading data: %s\n", pbl_errstr);
                free(data);
                continue;
            }
            
            // Print the first 32 bytes of data
            for (i = 0; i < datalen && i < 32; i++) {
                if (data[i] >= 32 && data[i] <= 126) {
                    printf("%c", data[i]);
                } else {
                    printf("\\x%02x", data[i]);
                }
            }
            if (datalen > 32) {
                printf("...");
            }
            
            free(data);
        }
        
        printf("\n");
        
    } while (pblIsamGet(isam, PBLNEXT, 0, key) >= 0);
    
    if (pbl_errno != PBL_ERROR_NOT_FOUND) {
        fprintf(stderr, "Error during iteration: %s\n", pbl_errstr);
    }
    
    pblIsamClose(isam);
}

int main(int argc, char* argv[]) {
    int is_keyfile = 0;
    int is_isamfile = 0;
    const char* filename = NULL;
    int i;
    
    // Parse command line arguments
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            // Option
            switch (argv[i][1]) {
                case 'k':
                    is_keyfile = 1;
                    break;
                case 'i':
                    is_isamfile = 1;
                    break;
                case 'h':
                    print_help();
                    return 0;
                default:
                    fprintf(stderr, "Unknown option: %s\n", argv[i]);
                    print_help();
                    return 1;
            }
        } else {
            // Filename
            if (filename) {
                fprintf(stderr, "Only one filename can be specified\n");
                print_help();
                return 1;
            }
            filename = argv[i];
        }
    }
    
    if (!filename) {
        fprintf(stderr, "No filename specified\n");
        print_help();
        return 1;
    }
    
    // If neither file type is specified, try to auto-detect
    if (!is_keyfile && !is_isamfile) {
        pblKeyFile_t* kf = pblKfOpen(filename, 0, NULL);
        if (kf) {
            pblKfClose(kf);
            is_keyfile = 1;
        } else {
            pblIsamFile_t* isam = pblIsamOpen(filename, 0, NULL, 0, NULL, NULL);
            if (isam) {
                pblIsamClose(isam);
                is_isamfile = 1;
            }
        }
        
        if (!is_keyfile && !is_isamfile) {
            fprintf(stderr, "Could not determine file type. Use -k or -i to specify.\n");
            return 1;
        }
    }
    
    if (is_keyfile) {
        dump_keyfile(filename);
    } else {
        dump_isamfile(filename);
    }
    
    return 0;
}
