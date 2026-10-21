"""ghl-jail: run one command inside a Windows sandbox, with no administrator rights and no drivers.

Two modes:
  container (default)  AppContainer. The child can only touch what it is granted, and has no network unless asked.
                       Limitation: on some Windows builds an AppContainer cannot open the NUL device, which breaks
                       tools that need it (git, Python's subprocess.DEVNULL).
  token                Restricted token. The child cannot read or write your user profile (SSH keys, cloud credentials,
                       browser data, ...) except the project directory, and NUL works. It does NOT block the network.

In both modes the child gets a clean environment (an allow-list: tokens, keys and passwords in the parent environment
never reach it), a private HOME/TEMP, and a job object that kills the whole process tree when the launcher exits.

This is harm reduction for untrusted command-line tools, not a security boundary. See README.md.

Usage:
    python ghl_jail.py run [--mode container|token] [--project DIR] [--net none|internet|lan]
                           [--allow-read PATH]... [--keep-env NAME]... -- CMD [ARGS]
    python ghl_jail.py cleanup
"""
import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
from ctypes import wintypes

PROFILE = "gaphunterlabs.jail"
CAPABILITIES = {"none": [], "internet": ["S-1-15-3-1"], "lan": ["S-1-15-3-1", "S-1-15-3-3"]}
ENV_ALLOW = {"PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "OS", "PROCESSOR_ARCHITECTURE",
             "NUMBER_OF_PROCESSORS", "LANG", "LC_ALL", "TERM", "COLORTERM", "NO_COLOR", "PYTHONIOENCODING", "PYTHONUTF8"}
NODE_FLAGS = "--preserve-symlinks --preserve-symlinks-main"
# Programs that open the NUL device by name at start-up (git does it in every command).
NEEDS_NUL = {"git"}
# Groups that stay in a restricted token's second access check. Files in the user profile grant none of them.
RESTRICTING = ["S-1-1-0", "S-1-5-32-545", "S-1-5-12"]  # Everyone, Users, Restricted

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_SUSPENDED = 0x00000004
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001
SE_GROUP_ENABLED = 0x00000004
JobObjectExtendedLimitInformation = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
INFINITE = 0xFFFFFFFF
ALREADY_EXISTS = 0x800700B7
INVALID = ctypes.c_void_p(-1).value
TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_ASSIGN_PRIMARY, TOKEN_ADJUST_DEFAULT = 0x0008, 0x0002, 0x0001, 0x0080
TokenDefaultDacl = 6
ACL_REVISION = 2
GENERIC_ALL = 0x10000000
TokenUser, TokenLogonSid = 1, 28

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi = ctypes.WinDLL("advapi32", use_last_error=True)
userenv = ctypes.WinDLL("userenv", use_last_error=True)
ole32 = ctypes.WinDLL("ole32")


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [("AppContainerSid", ctypes.c_void_p), ("Capabilities", ctypes.c_void_p),
                ("CapabilityCount", wintypes.DWORD), ("Reserved", wintypes.DWORD)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", ctypes.c_void_p), ("hStdOutput", ctypes.c_void_p), ("hStdError", ctypes.c_void_p)]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOps", "WriteOps", "OtherOps", "ReadBytes", "WriteBytes", "OtherBytes")]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


def _proto(fn, restype, *argtypes):
    fn.restype = restype
    fn.argtypes = list(argtypes)


_proto(k32.InitializeProcThreadAttributeList, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t))
_proto(k32.UpdateProcThreadAttribute, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p)
_proto(k32.DeleteProcThreadAttributeList, None, ctypes.c_void_p)
_proto(k32.CreateProcessW, wintypes.BOOL, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
       wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p)
_proto(advapi.CreateProcessAsUserW, wintypes.BOOL, ctypes.c_void_p, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
       wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p)
_proto(k32.WaitForSingleObject, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD)
_proto(k32.GetExitCodeProcess, wintypes.BOOL, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD))
_proto(k32.CloseHandle, wintypes.BOOL, ctypes.c_void_p)
_proto(k32.ResumeThread, wintypes.DWORD, ctypes.c_void_p)
_proto(k32.TerminateProcess, wintypes.BOOL, ctypes.c_void_p, wintypes.UINT)
_proto(k32.GetStdHandle, ctypes.c_void_p, wintypes.DWORD)
_proto(k32.GetCurrentProcess, ctypes.c_void_p)
_proto(k32.SetHandleInformation, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD)
_proto(k32.CreateJobObjectW, ctypes.c_void_p, ctypes.c_void_p, wintypes.LPCWSTR)
_proto(k32.SetInformationJobObject, wintypes.BOOL, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
_proto(k32.AssignProcessToJobObject, wintypes.BOOL, ctypes.c_void_p, ctypes.c_void_p)
_proto(k32.LocalFree, ctypes.c_void_p, ctypes.c_void_p)
_proto(advapi.ConvertStringSidToSidW, wintypes.BOOL, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p))
_proto(advapi.ConvertSidToStringSidW, wintypes.BOOL, ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
_proto(advapi.FreeSid, ctypes.c_void_p, ctypes.c_void_p)
_proto(advapi.OpenProcessToken, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p))
_proto(advapi.GetTokenInformation, wintypes.BOOL, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
_proto(advapi.CreateRestrictedToken, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
       ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
_proto(advapi.InitializeAcl, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD)
_proto(advapi.AddAccessAllowedAce, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p)
_proto(advapi.SetTokenInformation, wintypes.BOOL, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
_proto(userenv.CreateAppContainerProfile, ctypes.c_long, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p))
_proto(userenv.DeriveAppContainerSidFromAppContainerName, ctypes.c_long, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p))
_proto(userenv.DeleteAppContainerProfile, ctypes.c_long, wintypes.LPCWSTR)
_proto(userenv.GetAppContainerFolderPath, ctypes.c_long, wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPWSTR))
_proto(ole32.CoTaskMemFree, None, ctypes.c_void_p)


class JailError(Exception):
    pass


def sid_string(psid):
    out = wintypes.LPWSTR()
    if not advapi.ConvertSidToStringSidW(psid, ctypes.byref(out)):
        raise JailError("ConvertSidToStringSidW failed")
    text = out.value
    k32.LocalFree(ctypes.cast(out, ctypes.c_void_p))
    return text


def sid_from_string(text):
    sid = ctypes.c_void_p()
    if not advapi.ConvertStringSidToSidW(text, ctypes.byref(sid)):
        raise JailError(f"bad SID {text}")
    return sid


# ---------------------------------------------------------------- container mode

def container_sid():
    """Create the AppContainer profile (no admin needed) or derive its SID when it already exists."""
    psid = ctypes.c_void_p()
    hr = userenv.CreateAppContainerProfile(PROFILE, "Gap Hunter Labs jail", "Sandbox for untrusted CLI tools", None, 0, ctypes.byref(psid)) & 0xFFFFFFFF
    if hr == ALREADY_EXISTS:
        hr = userenv.DeriveAppContainerSidFromAppContainerName(PROFILE, ctypes.byref(psid)) & 0xFFFFFFFF
    if hr != 0:
        raise JailError(f"AppContainer profile failed: HRESULT 0x{hr:08X}")
    return psid


def container_home(sid_text):
    path = wintypes.LPWSTR()
    hr = userenv.GetAppContainerFolderPath(sid_text, ctypes.byref(path)) & 0xFFFFFFFF
    if hr != 0:
        raise JailError(f"GetAppContainerFolderPath failed: HRESULT 0x{hr:08X}")
    value = path.value
    ole32.CoTaskMemFree(ctypes.cast(path, ctypes.c_void_p))
    home = os.path.join(value, "Temp")
    os.makedirs(home, exist_ok=True)
    return home


# ---------------------------------------------------------------- token mode

def token_info(token, info_class):
    needed = wintypes.DWORD()
    advapi.GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
    buf = ctypes.create_string_buffer(needed.value)
    if not advapi.GetTokenInformation(token, info_class, buf, needed.value, ctypes.byref(needed)):
        raise JailError(f"GetTokenInformation({info_class}) failed: error {ctypes.get_last_error()}")
    return buf


def logon_sid_text(token):
    """The logon-session SID: every process of this login has it, so granting it exposes nothing new to you."""
    buf = token_info(token, TokenLogonSid)
    group_count = ctypes.c_uint32.from_buffer(buf).value
    if group_count < 1:
        raise JailError("no logon SID in the token")
    first = SID_AND_ATTRIBUTES.from_buffer(buf, ctypes.sizeof(ctypes.c_void_p))  # TOKEN_GROUPS.Groups[0], 8-byte aligned
    return sid_string(first.Sid)


def restricted_token():
    """Restricted copy of the current token: your user SID turned deny-only, and a second access check against
    Everyone / Users / Restricted / logon SID. Privileges are kept on purpose: a standard user holds only harmless ones, and
    deleting 'bypass traverse checking' makes the token unable to walk through your profile folders. Returns (token, logon SID)."""
    base = ctypes.c_void_p()
    if not advapi.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, ctypes.byref(base)):
        raise JailError(f"OpenProcessToken failed: error {ctypes.get_last_error()}")
    # The restricted token inherits the access rights of this handle: without ASSIGN_PRIMARY, process creation fails (5).
    try:
        logon_text = logon_sid_text(base)
        user_buf = token_info(base, TokenUser)
        user = SID_AND_ATTRIBUTES.from_buffer(user_buf)
        disable = (SID_AND_ATTRIBUTES * 1)(SID_AND_ATTRIBUTES(user.Sid, 0))
        sids = [sid_from_string(t) for t in RESTRICTING + [logon_text]]
        restrict = (SID_AND_ATTRIBUTES * len(sids))(*[SID_AND_ATTRIBUTES(s, 0) for s in sids])
        new = ctypes.c_void_p()
        if not advapi.CreateRestrictedToken(base, 0, 1, disable, 0, None, len(sids), restrict, ctypes.byref(new)):
            raise JailError(f"CreateRestrictedToken failed: error {ctypes.get_last_error()}")
        system = sid_from_string("S-1-5-18")
        try:
            set_default_dacl(new, [user.Sid, system, sids[-1]])
        finally:
            k32.LocalFree(system)
            for s in sids:
                k32.LocalFree(s)
        return new, logon_text
    finally:
        k32.CloseHandle(base)


def set_default_dacl(token, sids):
    """Objects the child creates, including its own process object, get this DACL. With only the (deny-only) user SID in
    it, the child cannot open itself, and APIs that do (the legacy CryptoAPI used to seed OpenSSL, for example) fail with
    access denied. Adding the logon SID lets the child see itself without widening its access to your files."""
    acl = ctypes.create_string_buffer(1024)
    if not advapi.InitializeAcl(acl, ctypes.sizeof(acl), ACL_REVISION):
        raise JailError("InitializeAcl failed")
    for sid in sids:
        if not advapi.AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sid):
            raise JailError(f"AddAccessAllowedAce failed: error {ctypes.get_last_error()}")
    tdd = ctypes.c_void_p(ctypes.addressof(acl))  # TOKEN_DEFAULT_DACL { PACL DefaultDacl; }
    if not advapi.SetTokenInformation(token, TokenDefaultDacl, ctypes.byref(tdd), ctypes.sizeof(tdd)):
        raise JailError(f"SetTokenInformation(TokenDefaultDacl) failed: error {ctypes.get_last_error()}")


# ---------------------------------------------------------------- shared helpers

STATE_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "ghl-jail")
STATE_FILE = os.path.join(STATE_DIR, "grants.json")


def _load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _record(sid_text, path):
    state = _load_state()
    paths = state.setdefault(sid_text, [])
    if path not in paths:
        paths.append(path)
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1)


def grant(path, sid_text, mode, notes):
    """Give a SID access to a path the current user owns, and remember it so `cleanup` can take it back.
    mode: 'M' modify, 'RX' read and execute."""
    spec = f"*{sid_text}:(OI)(CI)({mode})" if os.path.isdir(path) else f"*{sid_text}:({mode})"
    p = subprocess.run(["icacls", path, "/grant", spec, "/C"], capture_output=True, text=True)
    if p.returncode != 0:
        notes.append(f"could not grant {mode} on {path}: {(p.stdout + p.stderr).strip()[:120]}")
        return False
    _record(sid_text, path)
    return True


def clean_environment(keep, home, extra):
    env = {k: v for k, v in os.environ.items() if k.upper() in ENV_ALLOW or k in keep}
    env.update({"HOME": home, "USERPROFILE": home, "APPDATA": home, "LOCALAPPDATA": home, "TEMP": home, "TMP": home,
                "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"})
    # Node resolves the real path of every script by stat-ing each parent folder up to the drive root, which the sandbox
    # denies, and then aborts. Keeping symlinked paths as given skips that walk; every Node child (npm) inherits it.
    env["NODE_OPTIONS"] = " ".join(filter(None, [env.get("NODE_OPTIONS", ""), NODE_FLAGS]))
    env.update(extra)
    return env


def environment_block(env):
    text = "".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper())) + "\0"
    return ctypes.create_unicode_buffer(text, len(text) + 1)


def resolve_program(command, env_path):
    exe = shutil.which(command[0], path=env_path) or shutil.which(command[0])
    if not exe:
        raise JailError(f"program not found: {command[0]}")
    return os.path.abspath(exe)


def make_job():
    job = k32.CreateJobObjectW(None, None)
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not k32.SetInformationJobObject(job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
        raise JailError("SetInformationJobObject failed")
    return job


def std_handles():
    handles = []
    for which in (-10, -11, -12):  # stdin, stdout, stderr
        h = k32.GetStdHandle(which & 0xFFFFFFFF)
        if h in (None, 0, INVALID):
            handles.append(None)
            continue
        k32.SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
        handles.append(h)
    return handles


def choose_mode(command):
    """auto: container (no network) unless the program is known to need the NUL device, which AppContainers cannot open on
    some Windows builds. The switch is always announced, because token mode does not restrict the network."""
    name = os.path.splitext(os.path.basename(command[0]))[0].lower()
    if name in NEEDS_NUL:
        print(f"[ghl-jail] auto: {name} needs the NUL device, using token mode (network NOT restricted)", file=sys.stderr)
        return "token"
    return "container"


def run(command, project, mode="container", net="none", allow_read=(), keep_env=(), quiet=False, extra_env=None):
    project = os.path.abspath(project)
    if not os.path.isdir(project):
        raise JailError(f"project directory not found: {project}")
    notes, to_free, token = [], [], None
    if mode == "auto":
        mode = choose_mode(command)
    if mode == "container":
        psid = container_sid()
        principal = sid_string(psid)
        home = container_home(principal)
    else:
        token, principal = restricted_token()
        psid = None
        home = os.path.join(STATE_DIR, "home")
        os.makedirs(home, exist_ok=True)
        grant(home, principal, "M", notes)
    env = clean_environment(set(keep_env), home, extra_env or {})
    exe = resolve_program(command, env.get("PATH", ""))
    script = None
    if exe.lower().endswith((".cmd", ".bat")):
        # Wrapper scripts (npm.cmd, yarn.cmd, ...) run through cmd.exe; the sandbox gets read access to the script's folder,
        # which usually also holds the real program (node.exe next to npm.cmd).
        script, exe = exe, resolve_program(["cmd.exe"], env.get("PATH", ""))
    grant(project, principal, "M", notes)
    paths = {os.path.dirname(script or exe), *map(os.path.abspath, allow_read)}
    for path in paths:
        grant(path, principal, "RX", notes)
    if not quiet:
        extra = f", net {net}" if mode == "container" else ", network NOT restricted in this mode"
        print(f"[ghl-jail] mode {mode}, project {project}{extra}, {len(env)} environment variables", file=sys.stderr)
        for n in notes:
            print(f"[ghl-jail] warning: {n}", file=sys.stderr)

    handles = std_handles()
    listed = [h for h in dict.fromkeys(handles) if h]
    handle_list = (ctypes.c_void_p * max(1, len(listed)))(*listed)
    cap_array = (SID_AND_ATTRIBUTES * max(1, len(CAPABILITIES[net])))()
    count = 1 + (mode == "container")
    size = ctypes.c_size_t()
    k32.InitializeProcThreadAttributeList(None, count, 0, ctypes.byref(size))
    attrs = ctypes.create_string_buffer(size.value)
    if not k32.InitializeProcThreadAttributeList(attrs, count, 0, ctypes.byref(size)):
        raise JailError("InitializeProcThreadAttributeList failed")
    sc = None
    if mode == "container":
        for i, text in enumerate(CAPABILITIES[net]):
            sid = sid_from_string(text)
            to_free.append(sid)
            cap_array[i].Sid = sid
            cap_array[i].Attributes = SE_GROUP_ENABLED
        sc = SECURITY_CAPABILITIES(psid, ctypes.cast(cap_array, ctypes.c_void_p) if to_free else None, len(to_free), 0)
        if not k32.UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, ctypes.byref(sc), ctypes.sizeof(sc), None, None):
            raise JailError("UpdateProcThreadAttribute (capabilities) failed")
    if listed and not k32.UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handle_list, ctypes.sizeof(ctypes.c_void_p) * len(listed), None, None):
        raise JailError("UpdateProcThreadAttribute (handle list) failed")

    si = STARTUPINFOEXW()
    si.StartupInfo.cb = ctypes.sizeof(si)
    si.lpAttributeList = ctypes.cast(attrs, ctypes.c_void_p)
    if all(handles):
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = handles
    pi = PROCESS_INFORMATION()
    job = make_job()
    args = command[1:]
    if script:
        # /d: skip AutoRun commands; /s with outer quotes: cmd strips exactly those quotes and keeps the rest intact.
        text = f'"{exe}" /d /s /c "' + subprocess.list2cmdline([script, *args]) + '"'
    elif os.path.basename(exe).lower() == "cmd.exe" and args[:1] and args[0].lower() in ("/c", "/k"):
        # cmd.exe does not follow the C runtime quoting rules: pass its command text verbatim.
        text = f'"{exe}" {args[0]} ' + " ".join(args[1:])
    else:
        text = subprocess.list2cmdline([exe, *args])
    cmdline = ctypes.create_unicode_buffer(text)
    flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED
    block = environment_block(env)
    if mode == "container":
        ok = k32.CreateProcessW(exe, cmdline, None, None, True, flags, block, project, ctypes.byref(si), ctypes.byref(pi))
    else:
        ok = advapi.CreateProcessAsUserW(token, exe, cmdline, None, None, True, flags, block, project, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise JailError(f"process creation failed: error {ctypes.get_last_error()}")
    try:
        if not k32.AssignProcessToJobObject(job, pi.hProcess):
            k32.TerminateProcess(pi.hProcess, 1)
            raise JailError(f"AssignProcessToJobObject failed: error {ctypes.get_last_error()}")
        k32.ResumeThread(pi.hThread)
        k32.WaitForSingleObject(pi.hProcess, INFINITE)
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
        return code.value
    finally:
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(job)
        k32.DeleteProcThreadAttributeList(attrs)
        for sid in to_free:
            k32.LocalFree(sid)
        if psid is not None:
            advapi.FreeSid(psid)
        if token is not None:
            k32.CloseHandle(token)


def cleanup():
    """Take back every access entry the launcher granted, delete the container profile and the launcher's own folder."""
    removed, failed = 0, []
    for sid_text, paths in _load_state().items():
        for path in paths:
            if not os.path.exists(path):
                continue
            p = subprocess.run(["icacls", path, "/remove:g", f"*{sid_text}", "/C", "/Q"], capture_output=True, text=True)
            if p.returncode == 0:
                removed += 1
            else:
                failed.append(path)
    psid = container_sid()
    sid_text = sid_string(psid)
    advapi.FreeSid(psid)
    hr = userenv.DeleteAppContainerProfile(PROFILE) & 0xFFFFFFFF
    shutil.rmtree(STATE_DIR, ignore_errors=bool(not failed))
    print(f"access entries removed from {removed} path(s)" + (f"; could not clean: {failed}" if failed else ""))
    print(f"profile {PROFILE} ({sid_text}) deleted" if hr == 0 else f"profile delete failed: HRESULT 0x{hr:08X}")
    return 0 if hr == 0 and not failed else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ghl-jail", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run a command inside the jail")
    r.add_argument("--mode", choices=["container", "token", "auto"], default="container",
                   help="auto: container, or token for programs that need the NUL device (git)")
    r.add_argument("--project", default=os.getcwd(), help="the only writable directory (default: current directory)")
    r.add_argument("--net", choices=sorted(CAPABILITIES), default="none", help="container mode only")
    r.add_argument("--allow-read", action="append", default=[], metavar="PATH", help="extra path the command may read")
    r.add_argument("--keep-env", action="append", default=[], metavar="NAME", help="environment variable to pass through")
    r.add_argument("--quiet", action="store_true")
    r.add_argument("command", nargs=argparse.REMAINDER)
    sub.add_parser("cleanup", help="delete the container profile")
    args = ap.parse_args(argv)
    if args.cmd == "cleanup":
        return cleanup()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        ap.error("no command given (put it after --)")
    try:
        return run(command, args.project, args.mode, args.net, args.allow_read, args.keep_env, args.quiet)
    except JailError as exc:
        print(f"ghl-jail: {exc}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    sys.exit(main())
