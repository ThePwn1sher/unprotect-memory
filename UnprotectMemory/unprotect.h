#include <windows.h>
#include <stdio.h>
#include <psapi.h>

//#define DEBUG

/*
#include <stdio.h>
#include <Wincrypt.h>
#include <strsafe.h>
#pragma comment(lib, "crypt32.lib")
*/

#define UNPROTECTMEMORY_ADDR 0xee
#define PROTECTMEMORY_ADDR 0xdd
#define COPYMEMORY_ADDR 0xcc
#define EXITTHREAD_ADDR 0xbb
#define PROTECTED_BLOB_ADDR 0xaa
#define PROTECTED_BLOB_SIZE 0x99
#define RESULT_CAVE 0x88

void lowercase(char*);
long long get_remote_function_addr(HANDLE, char*, char*);
void insert_addr_shellcode(long long, size_t, UCHAR*, size_t, int);
DWORD getOffset(UCHAR*, int, size_t);

void _CryptUnprotectMemory();
void print_hex(const char*);