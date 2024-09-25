#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void xor_encrypt(unsigned char* data, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

void base64_encode(const unsigned char* data, size_t input_length, unsigned char* encoded_data, size_t encoded_length) {
    static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;

    for (size_t i = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        if (j + 4 > encoded_length) {
            fprintf(stderr, "Not enough space in encoded_data.\n");
            return;
        }

        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = encoding_table[triple & 0x3F];
    }

    while (j < encoded_length) { // Only pad if buffer isnt filtered
        encoded_data[j++] = '=';
    }
    encoded_data[j] = '\0'; // null
}

void encrypt_data(unsigned char** data, int* length, unsigned char key, int rounds) {
    for (int r = 0; r < rounds; r++) { // multiple rounds
      
        xor_encrypt(*data, *length, key);
      
        size_t encoded_length = 4 * ((*length + 2) / 3);
        unsigned char* encoded_data = (unsigned char*)malloc(encoded_length + 1);
        if (encoded_data == NULL) {
            perror("Failed to allocate memory");
            exit(EXIT_FAILURE);  }
        base64_encode(*data, *length, encoded_data, encoded_length);

        printf("Round %d encoded data: %s\n", r + 1, encoded_data);

        free(*data);
        *data = (unsigned char*)malloc(encoded_length);
        if (*data == NULL) {
            perror("Failed to allocate memory for new data");
            exit(EXIT_FAILURE);
        }
        memcpy(*data, encoded_data, encoded_length);
        *length = encoded_length;
        free(encoded_data);
    }
}

int main() {
    unsigned char* shellcode = (unsigned char*)malloc(256);
    if (shellcode == NULL) {
        perror("Failed to allocate memory for shellcode");
        return EXIT_FAILURE;
    }

    memcpy(shellcode, "...shellcode...", 256); // Copy shellcode into memory

    unsigned char key = 0xAA;
    int length = 256;
    int rounds = 3;  // Number of encryption rounds
    encrypt_data(&shellcode, &length, key, rounds);

    // Output in hexadecimal format
    printf("Final encrypted shellcode after %d rounds: ", rounds);
    for (int i = 0; i < length; i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\n");
    system("pause");
    free(shellcode);
    return 0;
}
