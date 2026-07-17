const koffi = require('koffi');

const PROCESS_ALL_ACCESS = 0x1F0FFF;
const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const MEM_RELEASE = 0x8000;
const PAGE_EXECUTE_READWRITE = 0x40;
const PAGE_READWRITE = 0x04;
const TOKEN_ALL_ACCESS = 0xF01FF;
const SE_PRIVILEGE_ENABLED = 0x2;
const DUPLICATE_SAME_ACCESS = 0x2;
const TH32CS_SNAPPROCESS = 0x2;
const ERROR_NOT_ALL_ASSIGNED = 1300;
const TP_DIRECT_SIZE = 72;
const TP_DIRECT_CALLBACK_OFFSET = 56;

const kernel32 = koffi.load('kernel32.dll');
const ntdll = koffi.load('ntdll.dll');
const advapi32 = koffi.load('advapi32.dll');

const LUID = koffi.struct('LUID', {
    LowPart: 'uint32',
    HighPart: 'int32',
});

const LUID_AND_ATTRIBUTES = koffi.struct('LUID_AND_ATTRIBUTES', {
    Luid: LUID,
    Attributes: 'uint32',
});

const TOKEN_PRIVILEGES = koffi.struct('TOKEN_PRIVILEGES', {
    PrivilegeCount: 'uint32',
    Privileges: koffi.array(LUID_AND_ATTRIBUTES, 1),
});

const PROCESSENTRY32W = koffi.struct('PROCESSENTRY32W', {
    dwSize: 'uint32',
    cntUsage: 'uint32',
    th32ProcessID: 'uint32',
    th32DefaultHeapID: 'uintptr_t',
    th32ModuleID: 'uint32',
    cntThreads: 'uint32',
    th32ParentProcessID: 'uint32',
    pcPriClassBase: 'int32',
    dwFlags: 'uint32',
    szExeFile: koffi.array('uint16', 260),
});

const MEMORY_BASIC_INFORMATION = koffi.struct('MEMORY_BASIC_INFORMATION', {
    BaseAddress: 'uint64',
    AllocationBase: 'uint64',
    AllocationProtect: 'uint32',
    PartitionId: 'uint16',
    _pad1: 'uint16',
    RegionSize: 'uint64',
    State: 'uint32',
    Protect: 'uint32',
    Type: 'uint32',
    _pad2: 'uint32',
});

const GetCurrentProcess = kernel32.func('void* __stdcall GetCurrentProcess()');
const OpenProcess = kernel32.func('void* __stdcall OpenProcess(uint32 access, int inherit, uint32 pid)');
const CloseHandle = kernel32.func('int __stdcall CloseHandle(void* h)');
const GetLastError = kernel32.func('uint32 __stdcall GetLastError()');
const CreateToolhelp32Snapshot = kernel32.func('void* __stdcall CreateToolhelp32Snapshot(uint32 flags, uint32 pid)');
const Process32FirstW = kernel32.func('int __stdcall Process32FirstW(void* snap, _Inout_ PROCESSENTRY32W* entry)');
const Process32NextW = kernel32.func('int __stdcall Process32NextW(void* snap, _Inout_ PROCESSENTRY32W* entry)');
const VirtualAllocEx = kernel32.func('void* __stdcall VirtualAllocEx(void* proc, void* addr, uintptr_t size, uint32 type, uint32 protect)');
const VirtualFreeEx = kernel32.func('int __stdcall VirtualFreeEx(void* proc, void* addr, uintptr_t size, uint32 type)');
const VirtualQueryEx = kernel32.func('uintptr_t __stdcall VirtualQueryEx(void* proc, void* addr, _Inout_ MEMORY_BASIC_INFORMATION* mbi, uintptr_t len)');
const WriteProcessMemory = kernel32.func('int __stdcall WriteProcessMemory(void* proc, void* base, const void* buf, uintptr_t size, _Out_ uintptr_t* written)');
const ReadProcessMemory = kernel32.func('int __stdcall ReadProcessMemory(void* proc, void* base, _Out_ void* buf, uintptr_t size, _Out_ uintptr_t* read)');
const DuplicateHandle = kernel32.func('int __stdcall DuplicateHandle(void* srcProc, void* srcHandle, void* tgtProc, _Out_ void** tgtHandle, uint32 access, int inherit, uint32 options)');
const GetModuleHandleA = kernel32.func('void* __stdcall GetModuleHandleA(const char* name)');
const GetProcAddress = kernel32.func('void* __stdcall GetProcAddress(void* mod, const char* name)');

const OpenProcessToken = advapi32.func('int __stdcall OpenProcessToken(void* proc, uint32 access, _Out_ void** token)');
const LookupPrivilegeValueW = advapi32.func('int __stdcall LookupPrivilegeValueW(const uint16* sys, const uint16* name, _Out_ LUID* luid)');
const AdjustTokenPrivileges = advapi32.func('int __stdcall AdjustTokenPrivileges(void* token, int disableAll, TOKEN_PRIVILEGES* newState, uint32 bufLen, void* prev, void* retLen)');

const NtQueryObject = ntdll.func('int32 __stdcall NtQueryObject(void* handle, int32 infoClass, _Out_ void* info, uint32 infoLen, void* retLen)');
const ZwSetIoCompletion = ntdll.func('int32 __stdcall ZwSetIoCompletion(void* port, void* key, void* apc, int32 ioStatus, uintptr_t ioInfo)');

function ptrFromBigInt(addr) {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64LE(addr);
    return koffi.decode(buf, 'void*');
}

function setPrivilege(privilege, attributes) {
    const tokenOut = [null];
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, tokenOut)) {
        return false;
    }
    const token = tokenOut[0];

    const luid = {};
    const privBuf = Buffer.from(privilege + '\0', 'utf16le');
    if (!LookupPrivilegeValueW(null, privBuf, luid)) {
        CloseHandle(token);
        return false;
    }

    const tp = {
        PrivilegeCount: 1,
        Privileges: [{ Luid: luid, Attributes: attributes }],
    };

    const result = AdjustTokenPrivileges(token, 0, tp, koffi.sizeof(TOKEN_PRIVILEGES), null, null);
    const err = GetLastError();
    CloseHandle(token);
    return !!result && err !== ERROR_NOT_ALL_ASSIGNED;
}

function findProcessPid(targetName) {
    const snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    const snapAddr = koffi.address(snap);
    if (!snap || snapAddr === 0 || snapAddr === 0xFFFFFFFF || snapAddr === 0xFFFFFFFFFFFFFFFFn) {
        return 0;
    }

    const entry = {
        dwSize: koffi.sizeof(PROCESSENTRY32W),
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: new Array(260).fill(0),
    };

    let pid = 0;
    if (Process32FirstW(snap, entry)) {
        while (true) {
            let name = '';
            for (let i = 0; i < 260; i++) {
                if (entry.szExeFile[i] === 0) break;
                name += String.fromCharCode(entry.szExeFile[i]);
            }
            if (name.toLowerCase() === targetName.toLowerCase()) {
                pid = entry.th32ProcessID;
                break;
            }
            if (!Process32NextW(snap, entry)) break;
        }
    }
    CloseHandle(snap);
    return pid;
}

const RBX_PRINT = 0;
const RBX_INFO = 1;
const RBX_WARNING = 2;
const RBX_ERROR = 3;

const RBX_LEVEL_MAP = {
    [RBX_PRINT]: 0,
    [RBX_INFO]: 1,
    [RBX_WARNING]: 2,
    [RBX_ERROR]: 3,
};

function buildShellcode(message, rbxLevel) {
    const k32 = GetModuleHandleA('kernel32.dll');
    const gmhaPtr = GetProcAddress(k32, 'GetModuleHandleA');
    const gmhaAddr = koffi.address(gmhaPtr);

    const rawLevel = RBX_LEVEL_MAP[rbxLevel] !== undefined ? RBX_LEVEL_MAP[rbxLevel] : 1;
    const msgBytes = Buffer.from(message + '\0', 'utf-8');

    const parts = [];

    parts.push(Buffer.from([0x48, 0x83, 0xEC, 0x28]));
    parts.push(Buffer.from([0x33, 0xC9]));

    const movRax = Buffer.alloc(10);
    movRax[0] = 0x48;
    movRax[1] = 0xB8;
    movRax.writeBigUInt64LE(BigInt(gmhaAddr), 2);
    parts.push(movRax);

    parts.push(Buffer.from([0xFF, 0xD0]));

    const addRax = Buffer.alloc(6);
    addRax[0] = 0x48;
    addRax[1] = 0x05;
    addRax.writeUInt32LE(0x470C4E0, 2);
    parts.push(addRax);

    parts.push(Buffer.from([0x49, 0x89, 0xC2]));

    const movEcx = Buffer.alloc(5);
    movEcx[0] = 0xB9;
    movEcx.writeUInt32LE(rawLevel, 1);
    parts.push(movEcx);

    parts.push(Buffer.from([0x48, 0x8D, 0x15, 0x08, 0x00, 0x00, 0x00]));
    parts.push(Buffer.from([0x41, 0xFF, 0xD2]));
    parts.push(Buffer.from([0x48, 0x83, 0xC4, 0x28]));
    parts.push(Buffer.from([0xC3]));
    parts.push(msgBytes);

    return Buffer.concat(parts);
}

function findIoCompletionHandle(process) {
    const typeInfoBuf = Buffer.alloc(10000);

    for (let i = 4; i < 8192; i += 4) {
        const dupHandleOut = [null];
        if (DuplicateHandle(process, i, GetCurrentProcess(), dupHandleOut, 0, 0, DUPLICATE_SAME_ACCESS)) {
            const dupHandle = dupHandleOut[0];
            const status = NtQueryObject(dupHandle, 2, typeInfoBuf, 10000, null);
            if (status >= 0) {
                const length = typeInfoBuf.readUInt16LE(0);
                const bufPtr = typeInfoBuf.readBigUInt64LE(8);

                if (bufPtr && length >= 2) {
                    const typeInfoBase = BigInt(koffi.address(typeInfoBuf));
                    const nameOffset = Number(bufPtr - typeInfoBase);
                    if (nameOffset >= 0 && nameOffset <= 10000 - length) {
                        try {
                            let name = '';
                            for (let c = 0; c < length; c += 2) {
                                const code = typeInfoBuf.readUInt16LE(nameOffset + c);
                                if (code === 0) break;
                                name += String.fromCharCode(code);
                            }
                            if (name === 'IoCompletion') {
                                return dupHandle;
                            }
                        } catch (e) {}
                    }
                }
            }
            CloseHandle(dupHandle);
        }
    }
    return null;
}

function findCodeCave(process) {
    let addr = 0n;

    while (true) {
        const mbi = {
            BaseAddress: 0,
            AllocationBase: 0,
            AllocationProtect: 0,
            PartitionId: 0,
            _pad1: 0,
            RegionSize: 0,
            State: 0,
            Protect: 0,
            Type: 0,
            _pad2: 0,
        };
        const result = VirtualQueryEx(process, ptrFromBigInt(addr), mbi, koffi.sizeof(MEMORY_BASIC_INFORMATION));
        if (!result) break;

        const base = BigInt(mbi.BaseAddress || 0);
        const size = BigInt(mbi.RegionSize || 0);

        if (mbi.State === MEM_COMMIT && mbi.Protect === PAGE_READWRITE && size >= BigInt(TP_DIRECT_SIZE)) {
            const chunkSize = 4096n;
            let off = 0n;

            while (off <= size - BigInt(TP_DIRECT_SIZE)) {
                const readSize = Number(size - off < chunkSize ? size - off : chunkSize);
                const buf = Buffer.alloc(readSize);
                const bytesReadOut = [0];

                const readAddr = base + off;
                if (!ReadProcessMemory(process, ptrFromBigInt(readAddr), buf, readSize, bytesReadOut)) {
                    break;
                }

                const bytesRead = bytesReadOut[0];
                for (let j = 0; j <= bytesRead - TP_DIRECT_SIZE; j++) {
                    let allZero = true;
                    for (let k = 0; k < TP_DIRECT_SIZE; k++) {
                        if (buf[j + k] !== 0) {
                            allZero = false;
                            break;
                        }
                    }
                    if (allZero) {
                        return base + off + BigInt(j);
                    }
                }
                off += chunkSize;
            }
        }

        const nextAddr = base + size;
        if (nextAddr <= addr || nextAddr >= 0x7FFFFFFFFFFFn) break;
        addr = nextAddr;
    }
    return null;
}

function inject(process, shellcodeAddr) {
    const completionHandle = findIoCompletionHandle(process);
    if (!completionHandle) {
        console.log('failed to find IoCompletion handle');
        return false;
    }

    const caveAddr = findCodeCave(process);
    if (!caveAddr) {
        console.log('failed to find suitable codecave in roblox');
        CloseHandle(completionHandle);
        return false;
    }

    const tpDirect = Buffer.alloc(TP_DIRECT_SIZE);
    tpDirect.writeBigUInt64LE(BigInt(shellcodeAddr), TP_DIRECT_CALLBACK_OFFSET);

    const bytesWrittenOut = [0];
    if (!WriteProcessMemory(process, ptrFromBigInt(caveAddr), tpDirect, TP_DIRECT_SIZE, bytesWrittenOut)) {
        const err = GetLastError();
        console.log(`failed to write TP_DIRECT structure to roblox: error 0x${err.toString(16).toUpperCase()}`);
        CloseHandle(completionHandle);
        return false;
    }

    const status = ZwSetIoCompletion(completionHandle, caveAddr, null, 0, 0);
    if (status < 0) {
        console.log(`failed to set IO completion, status 0x${(status >>> 0).toString(16).toUpperCase()}`);
        CloseHandle(completionHandle);
        return false;
    }

    CloseHandle(completionHandle);
    return true;
}

function printsploit(message, level = RBX_PRINT) {
    if (!setPrivilege('SeDebugPrivilege', SE_PRIVILEGE_ENABLED)) {
        console.log('privilege elevation failed. make sure to run as admin');
        return 1;
    }

    const pid = findProcessPid('RobloxPlayerBeta.exe');
    if (!pid) {
        console.log('target process not found');
        return 1;
    }

    const process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!process || koffi.address(process) === 0) {
        console.log('process access denied');
        return 1;
    }

    const shellcode = buildShellcode(message, level);
    const shellcodeRemote = VirtualAllocEx(process, null, shellcode.length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcodeRemote || koffi.address(shellcodeRemote) === 0) {
        console.log('failed to allocate shellcode memory');
        CloseHandle(process);
        return 1;
    }

    const bytesWrittenOut = [0];
    if (!WriteProcessMemory(process, shellcodeRemote, shellcode, shellcode.length, bytesWrittenOut)) {
        console.log('failed to write shellcode');
        VirtualFreeEx(process, shellcodeRemote, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    const shellcodeAddrNum = koffi.address(shellcodeRemote);
    if (!inject(process, shellcodeAddrNum)) {
        console.log('injection failed');
        VirtualFreeEx(process, shellcodeRemote, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    CloseHandle(process);
    console.log(`injected successfully: ${message}`);
    return 0;
}

module.exports = { printsploit, RBX_PRINT, RBX_INFO, RBX_WARNING, RBX_ERROR };

printsploit('testing fire, normal print');
printsploit('testing fire, error print', RBX_ERROR);
printsploit('testing fire, info print', RBX_INFO);
printsploit('testing fire, warning print', RBX_WARNING);
