#include <stdio.h>
#include <string.h>

void xor_encrypt(unsigned char* shellcode, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        shellcode[i] ^= key;
    }
}

int main() {
    unsigned char shellcode[] = {
    "....shellcode...."
    };

    int length = sizeof(shellcode);
    unsigned char key = 0xAA;
  
    printf("Original Shellcode: \n");
    for (int i = 0; i < length; i++) {
        printf("\\x%02x", shellcode[i]);
    }
    printf("\n");
    xor_encrypt(shellcode, length, key);
    printf("Encrypted Shellcode: \n");
    for (int i = 0; i < length; i++) {
        printf("\\x%02x", shellcode[i]);
    }
    printf("\n");
    return 0;
}
