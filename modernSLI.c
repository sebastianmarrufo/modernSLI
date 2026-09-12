/*
 * modernSLI - enable SLI on unsupported configs
 *
 * The site is found by signature rather than by offset. The string is only an
 * anchor; the flag offset is read out of the driver, so a layout change
 * between versions does not matter:
 *
 *      "RMSLIAlwaysApproved"
 *        -> the RIP-relative LEA that references it
 *          -> the byte store after it            (gives the flag offset)
 *            -> the cmp of that flag elsewhere   (the consumer)
 *              -> the flag test branch           (removed)
 *              -> test al,al and its branch      (forced)
 *
 *
 * Build: cl /nologo /W4 /O2 /MT /D_CRT_SECURE_NO_WARNINGS modernSLI.c
 *        /link advapi32.lib shell32.lib setupapi.lib crypt32.lib
 */

#include <windows.h>
#include <shellapi.h>
#include <setupapi.h>
#include <aclapi.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "crypt32.lib")

static const GUID DISPLAY_CLASS =
    { 0x4d36e968, 0xe325, 0x11ce,
      { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };

#define CERT_NAME "modernSLI Cert"

static unsigned char *g_img;
static size_t         g_len;
static IMAGE_SECTION_HEADER *g_sec;
static DWORD          g_nsec;


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
    size_t i, ref = 0, hit = 0, hitLen = 0, gate = 0, gateLen = 0;
    DWORD srva = 0, skip, target;
    size_t gateOff = 0, gateJlen = 0;
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
        gateOff = i + clen;                              /* remember it */
        gateJlen = jlen;

        for (q = i + clen + jlen; q + 8 < i + 0x50 && q + 2 <= g_len; q++) {
            if (g_img[q] != 0x84 || g_img[q + 1] != 0xC0) continue;
            if (!jcc(q + 2, &jlen, &target)) break;
            if (found && hit == q + 2) break;            /* REX double match */
            if (!found) {
                gate = gateOff; gateLen = gateJlen;
                hit = q + 2; hitLen = jlen;
                /* Going to SKIP means giving up, so remove it. Anything else
                 * is the approved path, so always take it. */
                makeJmp = (target != skip);
            }
            found++;
            break;
        }
    }
    if (!found) {
        printf("  approval branch not found - either this driver version is\n"
               "  not supported, or it has already been patched\n");
        return 0;
    }
    if (found > 1) { printf("  %d candidate branches - refusing to guess\n", found); return 0; }

    if (g_img[hit] == 0xEB || g_img[hit] == 0xE9 || g_img[hit] == 0x90) {
        printf("  already patched\n");
        return 0;
    }
    printf("  branch at rva %#lx: %s\n", to_rva(hit),
           makeJmp ? "making it unconditional" : "removing it");

    if (gate && gateLen) {
        memset(g_img + gate, 0x90, gateLen);
        printf("  flag test at rva %#lx: removed\n", to_rva(gate));
    }

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

static int elevated(void)
{
    HANDLE t; TOKEN_ELEVATION e; DWORD cb = sizeof(e); BOOL ok = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        if (GetTokenInformation(t, TokenElevation, &e, cb, &cb)) ok = e.TokenIsElevated;
        CloseHandle(t);
    }
    return ok;
}

static int relaunch(void)
{
    wchar_t exe[MAX_PATH];
    SHELLEXECUTEINFOW s = { sizeof(s) };
    if (!GetModuleFileNameW(NULL, exe, MAX_PATH)) return 0;
    s.fMask = SEE_MASK_NOCLOSEPROCESS;
    s.lpVerb = L"runas";
    s.lpFile = exe;
    s.lpParameters = L"--pause";     /* keep the new console open to read */
    s.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&s)) return 0;          /* declined, or failed */
    if (s.hProcess) {
        WaitForSingleObject(s.hProcess, INFINITE);
        CloseHandle(s.hProcess);
    }
    return 1;
}

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

static int have_selfsigned_cmdlet(void)
{
    OSVERSIONINFOEXA os;
    DWORDLONG m = 0;
    ZeroMemory(&os, sizeof(os));
    os.dwOSVersionInfoSize = sizeof(os);
    os.dwMajorVersion = 6;
    os.dwMinorVersion = 2;
    VER_SET_CONDITION(m, VER_MAJORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(m, VER_MINORVERSION, VER_GREATER_EQUAL);
    return VerifyVersionInfoA(&os, VER_MAJORVERSION | VER_MINORVERSION, m) != 0;
}

/* Windows 7: build the certificate with certreq and import it. */
static int make_cert_win7(void)
{
    char inf[MAX_PATH], cer[MAX_PATH], cmd[1024];
    UINT n = GetTempPathA(MAX_PATH, inf);
    FILE *f;

    strcpy_s(cer, MAX_PATH, inf);
    _snprintf_s(inf + n, MAX_PATH - n, _TRUNCATE, "modernSLI.inf");
    _snprintf_s(cer + n, MAX_PATH - n, _TRUNCATE, "modernSLI.cer");

    f = fopen(inf, "w");
    if (!f) return 0;
    fprintf(f,
        "[Version]\r\nSignature=\"$Windows NT$\"\r\n"
        "[NewRequest]\r\n"
        "Subject=\"CN=%s\"\r\n"
        "KeyLength=2048\r\n"
        "KeyUsage=0x80\r\n"
        "MachineKeySet=false\r\n"
        "KeySpec=2\r\n"
        "ProviderName=\"Microsoft Enhanced Cryptographic Provider v1.0\"\r\n"
        "ProviderType=1\r\n"
        "RequestType=Cert\r\n"
        "ValidityPeriod=Years\r\n"
        "ValidityPeriodUnits=5\r\n"
        "Exportable=true\r\n"
        "[EnhancedKeyUsageExtension]\r\n"
        "OID=1.3.6.1.5.5.7.3.3\r\n",
        CERT_NAME);
    fclose(f);

    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
                "certreq -q -new -f \"%s\" \"%s\"", inf, cer);
    if (!run(cmd)) return 0;

    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
                "certutil -addstore -f Root \"%s\"", cer);
    run(cmd);
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
                "certutil -addstore -f TrustedPublisher \"%s\"", cer);
    run(cmd);
    return 1;
}

typedef struct { DWORD cbSize; LPCWSTR pwszFileName; HANDLE hFile; } SGN_FILE;
typedef struct { DWORD cbSize; DWORD *pdwIndex; DWORD dwSubjectChoice;
                 SGN_FILE *pSignerFileInfo; } SGN_SUBJECT;
typedef struct { DWORD cbSize; PCCERT_CONTEXT pSigningCert; DWORD dwCertPolicy;
                 HCERTSTORE hCertStore; } SGN_CERT_STORE;
typedef struct { DWORD cbSize; DWORD dwCertChoice;
                 SGN_CERT_STORE *pCertStoreInfo; HWND hwnd; } SGN_CERT;
typedef struct { DWORD cbSize; ALG_ID algidHash; DWORD dwAttrChoice;
                 void *pAttrAuthcode; PCRYPT_ATTRIBUTES psAuthenticated;
                 PCRYPT_ATTRIBUTES psUnauthenticated; } SGN_SIGINFO;

typedef HRESULT (WINAPI *PFN_SIGNER_SIGN_EX)(DWORD, SGN_SUBJECT *, SGN_CERT *,
                                             SGN_SIGINFO *, void *, LPCWSTR,
                                             PCRYPT_ATTRIBUTES, void *, void **);

static int sign_native(const char *path)
{
    HCERTSTORE store;
    PCCERT_CONTEXT cert;
    HMODULE lib;
    PFN_SIGNER_SIGN_EX fn;
    SGN_FILE file;
    SGN_SUBJECT subj;
    SGN_CERT_STORE cs;
    SGN_CERT sc;
    SGN_SIGINFO si;
    DWORD index = 0;
    void *ctx = NULL;
    wchar_t wpath[MAX_PATH];
    HRESULT hr;

    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);

    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                          CERT_SYSTEM_STORE_CURRENT_USER, "MY");
    if (!store) { printf("  cannot open the certificate store\n"); return 0; }

    cert = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
                                      CERT_FIND_SUBJECT_STR_A, CERT_NAME, NULL);
    if (!cert) {
        printf("  certificate not found in the store\n");
        CertCloseStore(store, 0);
        return 0;
    }

    lib = LoadLibraryA("mssign32.dll");
    fn = lib ? (PFN_SIGNER_SIGN_EX)GetProcAddress(lib, "SignerSignEx") : NULL;
    if (!fn) {
        printf("  mssign32.dll unavailable\n");
        CertFreeCertificateContext(cert);
        CertCloseStore(store, 0);
        return 0;
    }

    ZeroMemory(&file, sizeof(file));
    file.cbSize = sizeof(file);
    file.pwszFileName = wpath;

    ZeroMemory(&subj, sizeof(subj));
    subj.cbSize = sizeof(subj);
    subj.pdwIndex = &index;
    subj.dwSubjectChoice = 1;              /* a file */
    subj.pSignerFileInfo = &file;

    ZeroMemory(&cs, sizeof(cs));
    cs.cbSize = sizeof(cs);
    cs.pSigningCert = cert;
    cs.dwCertPolicy = 2;                   /* build a chain */
    cs.hCertStore = store;

    ZeroMemory(&sc, sizeof(sc));
    sc.cbSize = sizeof(sc);
    sc.dwCertChoice = 2;                   /* from a store */
    sc.pCertStoreInfo = &cs;

    ZeroMemory(&si, sizeof(si));
    si.cbSize = sizeof(si);
    /* Windows 7 without the SHA-2 update cannot verify SHA256 kernel
     * signatures, so sign with SHA1 there. */
    si.algidHash = have_selfsigned_cmdlet() ? CALG_SHA_256 : CALG_SHA1;
    si.dwAttrChoice = 0;

    hr = fn(0, &subj, &sc, &si, NULL, NULL, NULL, NULL, &ctx);

    CertFreeCertificateContext(cert);
    CertCloseStore(store, 0);
    FreeLibrary(lib);

    if (hr != S_OK) {
        printf("  SignerSignEx failed: %#lx\n", (unsigned long)hr);
        return 0;
    }
    return 1;
}

/* Create the certificate if it is not already in the store. */
static int ensure_cert(void)
{
    char cmd[2048];

    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"if (Get-ChildItem Cert:\\CurrentUser\\My|"
        "?{$_.Subject -eq 'CN=%s' -and $_.HasPrivateKey}) {exit 0} "
        "else {exit 1}\"", CERT_NAME);
    if (run(cmd)) return 1;

    printf("  creating a certificate\n");

    if (!have_selfsigned_cmdlet()) return make_cert_win7();

    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"$ErrorActionPreference='Stop'; $s='CN=%s';"
        "$c=New-SelfSignedCertificate -Type CodeSigningCert -Subject $s "
        "-CertStoreLocation Cert:\\CurrentUser\\My "
        "-KeyUsage DigitalSignature -KeyExportPolicy Exportable "
        "-NotAfter (Get-Date).AddYears(5);"
        "$f=[IO.Path]::Combine($env:TEMP,'modernSLI.cer');"
        "Export-Certificate -Cert $c -FilePath $f -Force|Out-Null;"
        "certutil -addstore -f Root $f|Out-Null;"
        "certutil -addstore -f TrustedPublisher $f|Out-Null\"", CERT_NAME);
    return run(cmd);
}

static int sign(const char *path)
{
    int attempt;

    for (attempt = 0; attempt < 2; attempt++) {
        char cmd[512];
        if (!ensure_cert()) return 0;
        if (sign_native(path)) return 1;
        if (attempt == 0) {
            printf("  removing that certificate and retrying\n");
            _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
                        "certutil -user -delstore My \"%s\"", CERT_NAME);
            run(cmd);
        }
    }
    return 0;
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

static void fix_pe_checksum(void)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)g_img;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(g_img + dos->e_lfanew);
    DWORD *field = &nt->OptionalHeader.CheckSum;
    DWORD old = *field;
    unsigned long sum = 0;
    size_t i;

    *field = 0;
    for (i = 0; i + 1 < g_len; i += 2) {
        sum += (unsigned long)(g_img[i] | (g_img[i + 1] << 8));
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (g_len & 1) {
        sum += g_img[g_len - 1];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    *field = (DWORD)(sum + (unsigned long)g_len);
    printf("  checksum %#lx -> %#lx\n",
           (unsigned long)old, (unsigned long)*field);
}

/* Disable or re-enable the NVIDIA display adapters, which unloads and
 * reloads the driver so a replaced file takes effect without a reboot. */
static int devices(BOOL enable)
{
    HDEVINFO di = SetupDiGetClassDevsA(&DISPLAY_CLASS, 0, 0, DIGCF_PRESENT);
    SP_DEVINFO_DATA dev;
    DWORD i = 0;
    int n = 0;

    if (di == INVALID_HANDLE_VALUE) return 0;
    dev.cbSize = sizeof(dev);

    while (SetupDiEnumDeviceInfo(di, i++, &dev)) {
        char hw[512];
        SP_PROPCHANGE_PARAMS p;

        hw[0] = 0;
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

static int testsigning_on(void)
{
    typedef LONG (WINAPI *PFN_NQSI)(ULONG, PVOID, ULONG, PULONG);
    struct { ULONG Length; ULONG Options; } ci;
    HMODULE h;
    PFN_NQSI f;

    ci.Length = sizeof(ci);
    ci.Options = 0;
    h = GetModuleHandleA("ntdll.dll");
    f = h ? (PFN_NQSI)GetProcAddress(h, "NtQuerySystemInformation") : NULL;
    if (!f) return -1;
    if (f(103 /* SystemCodeIntegrityInformation */, &ci, sizeof(ci), NULL) != 0)
        return -1;
    return (ci.Options & 0x02) ? 1 : 0;    /* CODEINTEGRITY_OPTION_TESTSIGN */
}
static int owns_console(void)
{
    DWORD pids[2];
    DWORD n = GetConsoleProcessList(pids, 2);
    return n <= 1;
}

int main(int argc, char **argv)
{
    char live[MAX_PATH], tmp[MAX_PATH], sys32[MAX_PATH];
    int pause = (argc > 1 && !strcmp(argv[1], "--pause"));
    int wasSigned;
    FILE *f;
    UINT n;

    if (!elevated()) {
        if (relaunch()) return 0;               /* the elevated copy took over */
        printf("administrator rights are required\n");
        goto done;
    }

    if (!find_driver(live, MAX_PATH)) {
        printf("no NVIDIA driver found\n");
        goto done;
    }
    printf("driver: %s\n", live);

    n = GetTempPathA(MAX_PATH, tmp);
    _snprintf_s(tmp + n, MAX_PATH - n, _TRUNCATE, "nvlddmkm.patched.sys");
    if (!CopyFileA(live, tmp, FALSE) || !load_image(tmp)) {
        printf("could not stage a copy\n");
        goto done;
    }
    if (!patch()) {
        printf("\nNothing to do.\n");
        goto done;
    }

    fix_pe_checksum();

    f = fopen(tmp, "wb");
    if (!f) { printf("could not write the patched copy\n"); goto done; }
    fwrite(g_img, 1, g_len, f);
    fclose(f);

    wasSigned = testsigning_on();
    printf("test signing\n");
    if (wasSigned == 1) {
        printf("  already on\n");
    } else if (!run("bcdedit /set testsigning on")) {
        /*
         * Stop here rather than deploying. The patched driver is no longer
         * signed by NVIDIA, so without test signing it will not load at all -
         * and replacing the working driver with one that cannot load leaves
         * the machine on Basic Display until it is put back.
         */
        printf("  FAILED\n\n"
               "Test signing could not be enabled, and the patched driver\n"
               "cannot load without it. Nothing has been replaced.\n\n"
               "Almost always this is Secure Boot, which refuses the change\n"
               "with \"the value is protected by Secure Boot policy\":\n\n"
               "  1. reboot into UEFI firmware settings\n"
               "  2. turn Secure Boot off\n"
               "  3. boot Windows and run this again\n\n"
               "If Secure Boot is already off, try by hand to see the error:\n"
               "  bcdedit /set testsigning on\n\n");
        goto done;
    }

    printf("signing\n");
    if (!sign(tmp)) {
        printf("signing failed - the driver will not load unsigned\n");
        goto done;
    }

    printf("replacing (the screen may blank)\n");
    devices(FALSE);
    Sleep(2000);
    if (!CopyFileA(tmp, live, FALSE) &&
        (!take_ownership(live) || !CopyFileA(tmp, live, FALSE)))
        printf("  could not write %s (%lu)\n", live, GetLastError());
    else
        printf("  %s\n", live);

    n = GetSystemDirectoryA(sys32, MAX_PATH);
    _snprintf_s(sys32 + n, MAX_PATH - n, _TRUNCATE, "\\drivers\\nvlddmkm.sys");
    if (_stricmp(sys32, live) && GetFileAttributesA(sys32) != INVALID_FILE_ATTRIBUTES) {
        if (CopyFileA(tmp, sys32, FALSE) ||
            (take_ownership(sys32) && CopyFileA(tmp, sys32, FALSE)))
            printf("  %s\n", sys32);
    }
    devices(TRUE);

    if (wasSigned == 1)
        printf("\ndone.\n");
    else
        printf("\ndone - reboot to apply (test signing needs a restart)\n");

done:
    if (pause || owns_console()) {
        printf("\npress Enter to close...");
        getchar();
    }
    return 0;
}
