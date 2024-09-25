#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <stdint.h>

void xor_encrypt(unsigned char* data, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

void base64_encode(const unsigned char* data, size_t input_length, unsigned char* encoded_data) {
    static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = encoding_table[triple & 0x3F];
    }
}

int main() {
    unsigned char shellcode[] = {
    "...shelcode..."
    };

    unsigned char key = 0xAA;
    int length = sizeof(shellcode) - 1;
    xor_encrypt(shellcode, length, key);
  
    size_t encoded_length = 4 * ((length + 2) / 3);
    unsigned char encoded_shellcode[encoded_length + 1];
    base64_encode(shellcode, length, encoded_shellcode);  
  
    encoded_shellcode[encoded_length] = '\0';
    printf("Encoded shellcode: %s\n", encoded_shellcode);
    return 0;
}
