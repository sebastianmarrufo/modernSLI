/*
 * modernSLI - enable SLI on unsupported configs
 *
 * Two things are needed:
 *
 *   1. RMSLIAlwaysApproved=1 in the driver's registry keys. The driver reads
 *      this by name and sets an internal flag.
 *
 *   2. A one-instruction patch to the branch that flag gates. The flag alone
 *      only earns a call whose return value decides the outcome, and on an
 *      uncertified platform that call returns false.
 *
 * The patch site is found by signature rather than by offset:
 *
 *      "RMSLIAlwaysApproved"
 *        -> the RIP-relative LEA that references it
 *          -> the byte store after it            (gives the flag offset)
 *            -> the cmp of that flag elsewhere   (the consumer)
 *              -> test al,al and its branch      (what gets rewritten)
 *
 * Whether that branch is made unconditional or removed depends on which way
 * it points, which is worked out from the flag test rather than assumed.
 *
 *
 * Build: cl /nologo /W4 /O2 /MT /D_CRT_SECURE_NO_WARNINGS modernSLI.c
 *        /link advapi32.lib shell32.lib setupapi.lib
 */

#include <windows.h>
#include <shellapi.h>
#include <setupapi.h>
#include <aclapi.h>
#include <stdio.h>

static const GUID DISPLAY_CLASS =
    { 0x4d36e968, 0xe325, 0x11ce,
      { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };

#define CLASS_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\" \
                  "{4d36e968-e325-11ce-bfc1-08002be10318}"
#define CERT_NAME "SLI Patch Cert"

static unsigned char *g_img;
static size_t         g_len;
static IMAGE_SECTION_HEADER *g_sec;
static DWORD          g_nsec;

/* ---------------------------------------------------------------- image */

static int load_image(const char *path)
{
    FILE *f = fopen(path, "rb");
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    long n;

    if (!f) return 0;
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n <= 0x1000 || !(g_img = malloc((size_t)n))) { fclose(f); return 0; }
    g_len = fread(g_img, 1, (size_t)n, f);
    fclose(f);

    dos = (IMAGE_DOS_HEADER *)g_img;
    if (g_len != (size_t)n || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (IMAGE_NT_HEADERS64 *)(g_img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return 0;
    g_nsec = nt->FileHeader.NumberOfSections;
    g_sec  = IMAGE_FIRST_SECTION(nt);
    return 1;
}

static DWORD to_rva(size_t off)
{
    DWORD i;
    for (i = 0; i < g_nsec; i++) {
        IMAGE_SECTION_HEADER *s = &g_sec[i];
        if (s->PointerToRawData && off >= s->PointerToRawData &&
            off < (size_t)s->PointerToRawData + s->SizeOfRawData)
            return s->VirtualAddress + (DWORD)(off - s->PointerToRawData);
    }
    return 0;
}

/* -------------------------------------------------------------- locator */

/* Conditional jump: returns its length and where it goes. */
static int jcc(size_t off, size_t *len, DWORD *target)
{
    DWORD rva = to_rva(off);
    if (!rva || off + 2 > g_len) return 0;
    if (g_img[off] >= 0x70 && g_img[off] <= 0x7F) {
        *len = 2; *target = rva + 2 + (signed char)g_img[off + 1];
        return 1;
    }
    if (g_img[off] == 0x0F && off + 6 <= g_len &&
        g_img[off + 1] >= 0x80 && g_img[off + 1] <= 0x8F) {
        *len = 6; *target = rva + 6 + *(int *)(g_img + off + 2);
        return 1;
    }
    return 0;
}

static int patch(void)
{
    static const char anchor[] = "RMSLIAlwaysApproved";
    size_t i, ref = 0, hit = 0, hitLen = 0;
    DWORD srva = 0, skip, target;
    int flag = 0, found = 0, makeJmp = 0;

    /* the string */
    for (i = 0; i + sizeof(anchor) - 1 <= g_len; i++)
        if (!memcmp(g_img + i, anchor, sizeof(anchor) - 1)) { srva = to_rva(i); break; }
    if (!srva) { printf("  anchor string not found\n"); return 0; }

    /* lea reg, [rip+disp32] pointing at it */
    for (i = 0; i + 7 <= g_len && !ref; i++) {
        DWORD next;
        if ((g_img[i] & 0xF8) != 0x48 || g_img[i + 1] != 0x8D) continue;
        if ((g_img[i + 2] & 0xC7) != 0x05) continue;
        next = to_rva(i + 7);
        if (next && next + *(int *)(g_img + i + 3) == srva) ref = i;
    }
    if (!ref) { printf("  no reference to the anchor string\n"); return 0; }

    /*
     * The store just after the registry read gives the flag offset. Two
     * encodings occur: an immediate (C6 /0) and a register source (88 /r),
     * either optionally REX-prefixed.
     */
    for (i = ref; i < ref + 0x80 && i + 8 <= g_len && !flag; i++) {
        size_t o = i + ((g_img[i] >= 0x40 && g_img[i] <= 0x4F) ? 1 : 0);
        if ((g_img[o + 1] & 0x07) == 0x04) continue;          /* SIB */
        if (g_img[o] == 0xC6 && (g_img[o + 1] & 0xF8) == 0x80 && g_img[o + 6] == 1)
            flag = *(int *)(g_img + o + 2);
        else if (g_img[o] == 0x88 && (g_img[o + 1] & 0xC0) == 0x80)
            flag = *(int *)(g_img + o + 2);
    }
    if (!flag) { printf("  flag store not found\n"); return 0; }
    printf("  flag offset +%#x\n", (unsigned)flag);

    /* the consumer: cmp of that flag, then test al,al, then a branch */
    for (i = 0; i + 16 <= g_len; i++) {
        size_t o = i + ((g_img[i] >= 0x40 && g_img[i] <= 0x4F) ? 1 : 0);
        size_t clen, q, jlen;

        if ((g_img[o + 1] & 0x07) == 0x04) continue;
        if (g_img[o] == 0x80 && (g_img[o + 1] & 0xF8) == 0xB8 &&
            *(int *)(g_img + o + 2) == flag) clen = (o - i) + 7;
        else if (g_img[o] == 0x38 && (g_img[o + 1] & 0xC0) == 0x80 &&
                 *(int *)(g_img + o + 2) == flag) clen = (o - i) + 6;
        else continue;

        if (!jcc(i + clen, &jlen, &skip)) continue;      /* flag clear -> SKIP */

        for (q = i + clen + jlen; q + 8 < i + 0x50 && q + 2 <= g_len; q++) {
            if (g_img[q] != 0x84 || g_img[q + 1] != 0xC0) continue;
            if (!jcc(q + 2, &jlen, &target)) break;
            if (found && hit == q + 2) break;            /* REX double match */
            if (!found) {
                hit = q + 2; hitLen = jlen;
                /* Going to SKIP means giving up, so remove it. Anything else
                 * is the approved path, so always take it. */
                makeJmp = (target != skip);
            }
            found++;
            break;
        }
    }
    if (!found) { printf("  approval branch not found\n"); return 0; }
    if (found > 1) { printf("  %d candidate branches - refusing to guess\n", found); return 0; }

    if (g_img[hit] == 0xEB || g_img[hit] == 0xE9 || g_img[hit] == 0x90) {
        printf("  already patched\n");
        return 1;
    }
    printf("  branch at rva %#lx: %s\n", to_rva(hit),
           makeJmp ? "making it unconditional" : "removing it");

    if (!makeJmp) {
        memset(g_img + hit, 0x90, hitLen);
    } else if (hitLen == 2) {
        g_img[hit] = 0xEB;
    } else {
        int rel = *(int *)(g_img + hit + 2);
        g_img[hit] = 0xE9;                    /* one byte shorter than 0F 8x */
        *(int *)(g_img + hit + 1) = rel + 1;  /* so the target is unchanged  */
        g_img[hit + 5] = 0x90;
    }
    return 1;
}

/* ----------------------------------------------------------- privileges */

static int elevated(void)
{
    HANDLE t; TOKEN_ELEVATION e; DWORD cb = sizeof(e); BOOL ok = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        if (GetTokenInformation(t, TokenElevation, &e, cb, &cb)) ok = e.TokenIsElevated;
        CloseHandle(t);
    }
    return ok;
}

static void relaunch(void)
{
    wchar_t exe[MAX_PATH];
    SHELLEXECUTEINFOW s = { sizeof(s) };
    if (!GetModuleFileNameW(NULL, exe, MAX_PATH)) return;
    s.fMask = SEE_MASK_NOCLOSEPROCESS;
    s.lpVerb = L"runas";
    s.lpFile = exe;
    s.lpParameters = L"--pause";     /* keep the new console open to read */
    s.nShow = SW_SHOWNORMAL;
    if (ShellExecuteExW(&s) && s.hProcess) {
        WaitForSingleObject(s.hProcess, INFINITE);
        CloseHandle(s.hProcess);
    }
}

/* DriverStore files belong to TrustedInstaller; an admin still cannot write
 * them until the owner and DACL are changed. */
static int take_ownership(const char *path)
{
    HANDLE tok; TOKEN_PRIVILEGES tp; PSID adm = NULL; PACL acl = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    EXPLICIT_ACCESSA ea; int ok = 0; int i;
    static const char *privs[] = { SE_TAKE_OWNERSHIP_NAME, SE_RESTORE_NAME };

    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        for (i = 0; i < 2; i++) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValueA(NULL, privs[i], &tp.Privileges[0].Luid))
                AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(tok);
    }
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &adm))
        return 0;
    if (SetNamedSecurityInfoA((char *)path, SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION, adm, 0,0,0)) goto out;
    ZeroMemory(&ea, sizeof(ea));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = (char *)adm;
    if (SetEntriesInAclA(1, &ea, NULL, &acl)) goto out;
    ok = SetNamedSecurityInfoA((char *)path, SE_FILE_OBJECT,
                               DACL_SECURITY_INFORMATION, 0,0, acl, 0) == 0;
out:
    if (acl) LocalFree(acl);
    FreeSid(adm);
    return ok;
}

/* ------------------------------------------------------------- external */

static int run(const char *cmd)
{
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD code = 1;
    char *buf = _strdup(cmd);
    if (!buf) return 0;
    if (!CreateProcessA(NULL, buf, 0,0, FALSE, 0, 0,0, &si, &pi)) {
        free(buf); return 0;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); free(buf);
    return code == 0;
}

static int sign(const char *path)
{
    char cmd[3072];
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"$ErrorActionPreference='Stop'; $s='CN=%s';"
        "$c=Get-ChildItem Cert:\\CurrentUser\\My|?{$_.Subject -eq $s}|"
        "select -First 1;"
        "if(-not $c){$c=New-SelfSignedCertificate -Type CodeSigningCert "
        "-Subject $s -CertStoreLocation Cert:\\CurrentUser\\My "
        "-KeyUsage DigitalSignature -KeyExportPolicy Exportable "
        "-NotAfter (Get-Date).AddYears(5)};"
        "$f=[IO.Path]::Combine($env:TEMP,'modernSLI.cer');"
        "Export-Certificate -Cert $c -FilePath $f -Force|Out-Null;"
        "certutil -addstore -f Root $f|Out-Null;"
        "certutil -addstore -f TrustedPublisher $f|Out-Null;"
        "$r=Set-AuthenticodeSignature -FilePath '%s' -Certificate $c "
        "-HashAlgorithm SHA256;"
        "if($r.Status -ne 'Valid'){Write-Host $r.StatusMessage;exit 1}\"",
        CERT_NAME, path);
    return run(cmd);
}

// devices

static int devices(BOOL enable)
{
    HDEVINFO di = SetupDiGetClassDevsA(&DISPLAY_CLASS, 0,0, DIGCF_PRESENT);
    SP_DEVINFO_DATA dev = { sizeof(dev) };
    DWORD i = 0;
    int n = 0;

    if (di == INVALID_HANDLE_VALUE) return 0;
    while (SetupDiEnumDeviceInfo(di, i++, &dev)) {
        char hw[512] = { 0 };
        SP_PROPCHANGE_PARAMS p;
        if (!SetupDiGetDeviceRegistryPropertyA(di, &dev, SPDRP_HARDWAREID, 0,
                                               (PBYTE)hw, sizeof(hw), 0)) continue;
        if (!strstr(hw, "VEN_10DE")) continue;
        ZeroMemory(&p, sizeof(p));
        p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        p.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        p.StateChange = enable ? DICS_ENABLE : DICS_DISABLE;
        p.Scope = DICS_FLAG_CONFIGSPECIFIC;
        if (SetupDiSetClassInstallParamsA(di, &dev,
                (SP_CLASSINSTALL_HEADER *)&p, sizeof(p)) &&
            SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, di, &dev)) n++;
    }
    SetupDiDestroyDeviceInfoList(di);
    return n;
}

// registry

static void set_dword(HKEY root, const char *sub, const char *name, DWORD v)
{
    HKEY k;
    if (RegCreateKeyExA(root, sub, 0,0,0, KEY_SET_VALUE | KEY_WOW64_64KEY,
                        0, &k, 0)) return;
    RegSetValueExA(k, name, 0, REG_DWORD, (BYTE *)&v, sizeof(v));
    RegCloseKey(k);
}

/*
 * Which key the RM reads varies by branch, so write them all. The per-adapter
 * driver keys are enumerated rather than assumed: their indices change when a
 * driver is reinstalled.
 */
static void regkeys(void)
{
    static const char *fixed[] = {
        "SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Global\\NVTweak",
        "SYSTEM\\CurrentControlSet\\Services\\nvlddmkm",
    };
    HKEY cls;
    DWORD i = 0;
    size_t f;

    for (f = 0; f < 2; f++) {
        set_dword(HKEY_LOCAL_MACHINE, fixed[f], "RMSLIAlwaysApproved", 1);
        set_dword(HKEY_LOCAL_MACHINE, fixed[f], "RMDynamicSLIAllowed", 1);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, CLASS_KEY, 0,
                      KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &cls)) return;

    for (;;) {
        char name[16], sub[512], desc[256];
        DWORD cb = sizeof(name), dcb = sizeof(desc);
        HKEY dev;
        if (RegEnumKeyExA(cls, i++, name, &cb, 0,0,0,0)) break;
        if (cb != 4) continue;
        _snprintf_s(sub, sizeof(sub), _TRUNCATE, "%s\\%s", CLASS_KEY, name);
        desc[0] = 0;
        if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub, 0,
                           KEY_QUERY_VALUE | KEY_WOW64_64KEY, &dev)) {
            RegQueryValueExA(dev, "DriverDesc", 0,0, (BYTE *)desc, &dcb);
            RegCloseKey(dev);
        }
        if (!strstr(desc, "NVIDIA")) continue;
        set_dword(HKEY_LOCAL_MACHINE, sub, "RMSLIAlwaysApproved", 1);
        set_dword(HKEY_LOCAL_MACHINE, sub, "RMDynamicSLIAllowed", 1);
        printf("  %s (%s)\n", name, desc);
    }
    RegCloseKey(cls);
}


static int find_driver(char *out, size_t cch)
{
    HKEY k;
    char raw[MAX_PATH * 2], win[MAX_PATH];
    DWORD cb = sizeof(raw);
    UINT n;

    if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                       "SYSTEM\\CurrentControlSet\\Services\\nvlddmkm", 0,
                       KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k)) {
        int got = !RegQueryValueExA(k, "ImagePath", 0,0, (BYTE *)raw, &cb);
        RegCloseKey(k);
        if (got && GetWindowsDirectoryA(win, MAX_PATH)) {
            raw[cb < sizeof(raw) ? cb : sizeof(raw) - 1] = 0;
            if (!_strnicmp(raw, "\\SystemRoot\\", 12))
                _snprintf_s(out, cch, _TRUNCATE, "%s\\%s", win, raw + 12);
            else if (!_strnicmp(raw, "\\??\\", 4))
                strncpy_s(out, cch, raw + 4, _TRUNCATE);
            else
                ExpandEnvironmentStringsA(raw, out, (DWORD)cch);
            if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return 1;
        }
    }
    n = GetSystemDirectoryA(out, (UINT)cch);
    if (n) {
        _snprintf_s(out + n, cch - n, _TRUNCATE, "\\drivers\\nvlddmkm.sys");
        if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return 1;
    }
    return 0;
}


int main(int argc, char **argv)
{
    char live[MAX_PATH], tmp[MAX_PATH], sys32[MAX_PATH];
    int pause = (argc > 1 && !strcmp(argv[1], "--pause"));
    FILE *f;
    UINT n;

    if (!elevated()) { relaunch(); return 0; }

    if (!find_driver(live, MAX_PATH)) {
        printf("no NVIDIA driver found\n");
        goto done;
    }
    printf("driver: %s\n", live);

    /* Patch a copy - the live file is mapped and cannot be written. */
    n = GetTempPathA(MAX_PATH, tmp);
    _snprintf_s(tmp + n, MAX_PATH - n, _TRUNCATE, "nvlddmkm.patched.sys");
    if (!CopyFileA(live, tmp, FALSE) || !load_image(tmp)) {
        printf("could not stage a copy\n");
        goto done;
    }
    if (!patch()) goto done;

    f = fopen(tmp, "wb");
    if (!f) { printf("could not write the patched copy\n"); goto done; }
    fwrite(g_img, 1, g_len, f);
    fclose(f);

    printf("signing\n");
    if (!sign(tmp)) {
        printf("signing failed - the driver will not load unsigned\n");
        goto done;
    }

    printf("registry\n");
    regkeys();
    run("bcdedit /set testsigning on");

    printf("replacing (the screen may blank)\n");
    devices(FALSE);
    Sleep(2000);
    if (!CopyFileA(tmp, live, FALSE) &&
        (!take_ownership(live) || !CopyFileA(tmp, live, FALSE)))
        printf("  could not write %s (%lu)\n", live, GetLastError());
    else
        printf("  %s\n", live);

    /* Some packages also keep a copy here; update it if so. */
    n = GetSystemDirectoryA(sys32, MAX_PATH);
    _snprintf_s(sys32 + n, MAX_PATH - n, _TRUNCATE, "\\drivers\\nvlddmkm.sys");
    if (_stricmp(sys32, live) && GetFileAttributesA(sys32) != INVALID_FILE_ATTRIBUTES) {
        if (CopyFileA(tmp, sys32, FALSE) ||
            (take_ownership(sys32) && CopyFileA(tmp, sys32, FALSE)))
            printf("  %s\n", sys32);
    }
    devices(TRUE);

    printf("\ndone - reboot to apply\n");

done:
    if (pause) { printf("\npress Enter to close..."); getchar(); }
    return 0;
}
