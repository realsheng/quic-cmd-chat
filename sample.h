/*++ ... [前面的版权和注释部分保持不变] ... --*/

#define _CRT_SECURE_NO_WARNINGS 1
#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#ifdef _WIN32
#pragma warning(disable:5105)
#include <share.h>
#endif

#include <iostream>
#include <msquic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif
#include <mutex>
#include <list>
#include <string>

const QUIC_REGISTRATION_CONFIG RegConfig = { "QUICProject", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };
const uint16_t UdpPort = 4567;
const uint64_t IdleTimeoutMs = 0;
const uint32_t SendBufferLength = 1024;

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;
HQUIC Configuration;
QUIC_TLS_SECRETS ClientSecrets = { 0 };
const char* SslKeyLogEnvVar = "SSLKEYLOGFILE";

// 每个客户端连接的节点
typedef struct _CLIENT_NODE {
    uint32_t times; // 通信次数
    const char* name;
    HQUIC Stream;
} CLIENT_NODE;

typedef struct _SERVER_CONTEXT {
    std::mutex lock_;  
    std::list<std::shared_ptr<_CLIENT_NODE>> client_list_; 
} SERVER_CONTEXT;

typedef struct {
    const char* name;
    HQUIC Stream;
    bool IsServer;
    struct _SERVER_CONTEXT* ServerContext; // 服务器上下文结构体
} CHAT_CONTEXT;

/**
 * 打印使用帮助信息。
 *
 * 此函数展示了如何使用 quicsample 程序以客户端、多客户端或服务器模式运行。
 * 它根据是否启用了预览功能来决定是否显示多客户端相关的帮助信息。
 **/
void PrintUsage()
{
    printf(
        "\n"
        "QUICProject 运行一个简单的客户端或服务器。\n"
        "\n"
        "用法:\n"
        "\n"
        // 单客户端模式
        "  QUICProject.exe -client -unsecure -name:{Username} -target:{IPAddress|Hostname} [-ticket:<ticket>]\n"
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
        // 多客户端模式（仅当启用了预览功能时显示）
        "  QUICProject.exe -multiclient -count:<N> -unsecure -target:{IPAddress|Hostname}\n"
#endif
        // 服务器模式（两种认证方式：证书哈希或文件路径）
        "  QUICProject.exe -server -cert_hash:<...>\n"
        "  QUICProject.exe -server -cert_file:<...> -key_file:<...> [-password:<...>]\n"
        "\n"
        // 参数说明可以进一步添加在这里
        "参数说明:\n"
        "  -client: 启动客户端模式。\n"
        "  -multiclient: 启动多客户端模式（需要启用预览功能）。\n"
        "  -server: 启动服务器模式。\n"
        "  -unsecure: 在客户端模式下禁用证书验证。\n"
        "  -name: 在客户端模式下输入用户名。\n"
        "  -target: 指定目标服务器的 IP 地址或主机名。\n"
        "  -ticket: （可选）提供会话恢复票据。\n"
        "  -count: 在多客户端模式下指定要创建的连接数。\n"
        "  -cert_hash: 在服务器模式下使用证书哈希进行身份验证。\n"
        "  -cert_file: 在服务器模式下使用证书文件路径进行身份验证。\n"
        "  -key_file: 在服务器模式下指定私钥文件路径。\n"
        "  -password: （可选）如果私钥文件受密码保护，则提供该密码。\n"
    );
}

// 检查是否包含指定标志
BOOLEAN GetFlag(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
)
{
    const size_t nameLen = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0
            && strlen(argv[i]) == nameLen + 1) {
            return TRUE;
        }
    }
    return FALSE;
}

// 获取指定参数的值
_Ret_maybenull_  // 表明该函数可能返回一个空指针（NULL）。
_Null_terminated_ // 返回值是一个以空字符（'\0'）结尾的字符串
const char* GetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
)
{
    const size_t nameLen = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0
            && strlen(argv[i]) > 1 + nameLen + 1
            && *(argv[i] + 1 + nameLen) == ':') {
            return argv[i] + 1 + nameLen + 1;
        }
    }
    return NULL;
}

// 解码十六进制字符
uint8_t DecodeHexChar(
    _In_ char c
)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return 0;
}

// 解码十六进制缓冲区
uint32_t DecodeHexBuffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
    uint8_t* OutBuffer
)
{
    uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++) {
        OutBuffer[i] =
            (DecodeHexChar(HexBuffer[i * 2]) << 4) |
            DecodeHexChar(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}

// 编码缓冲区为十六进制字符串
void EncodeHexBuffer(
    _In_reads_(BufferLen) uint8_t * Buffer,
    _In_ uint8_t BufferLen,
    _Out_writes_bytes_(2 * BufferLen) char* HexString
)
{
#define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
    for (uint8_t i = 0; i < BufferLen; i++) {
        HexString[i * 2] = HEX_TO_CHAR(Buffer[i] >> 4);
        HexString[i * 2 + 1] = HEX_TO_CHAR(Buffer[i] & 0xf);
    }
}

// 写入SSL密钥日志文件
void WriteSslKeyLogFile(
    _In_z_ const char* FileName,
    _In_ QUIC_TLS_SECRETS * TlsSecrets
)
{
    printf("Writing SSLKEYLOGFILE at %s\n", FileName);
    FILE* File = NULL;
#ifdef _WIN32
    File = _fsopen(FileName, "ab", _SH_DENYNO);
#else
    File = fopen(FileName, "ab");
#endif

    if (File == NULL) {
        printf("Failed to open sslkeylogfile %s\n", FileName);
        return;
    }
    if (fseek(File, 0, SEEK_END) == 0 && ftell(File) == 0) {
        fprintf(File, "# TLS 1.3 secrets log file, generated by msquic\n");
    }

    char ClientRandomBuffer[(2 * sizeof(((QUIC_TLS_SECRETS*)0)->ClientRandom)) + 1] = { 0 };

    char TempHexBuffer[(2 * QUIC_TLS_SECRETS_MAX_SECRET_LEN) + 1] = { 0 };
    if (TlsSecrets->IsSet.ClientRandom) {
        EncodeHexBuffer(
            TlsSecrets->ClientRandom,
            (uint8_t)sizeof(TlsSecrets->ClientRandom),
            ClientRandomBuffer);
    }

    if (TlsSecrets->IsSet.ClientEarlyTrafficSecret) {
        EncodeHexBuffer(
            TlsSecrets->ClientEarlyTrafficSecret,
            TlsSecrets->SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "CLIENT_EARLY_TRAFFIC_SECRET %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets->IsSet.ClientHandshakeTrafficSecret) {
        EncodeHexBuffer(
            TlsSecrets->ClientHandshakeTrafficSecret,
            TlsSecrets->SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets->IsSet.ServerHandshakeTrafficSecret) {
        EncodeHexBuffer(
            TlsSecrets->ServerHandshakeTrafficSecret,
            TlsSecrets->SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets->IsSet.ClientTrafficSecret0) {
        EncodeHexBuffer(
            TlsSecrets->ClientTrafficSecret0,
            TlsSecrets->SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "CLIENT_TRAFFIC_SECRET_0 %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets->IsSet.ServerTrafficSecret0) {
        EncodeHexBuffer(
            TlsSecrets->ServerTrafficSecret0,
            TlsSecrets->SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "SERVER_TRAFFIC_SECRET_0 %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    fflush(File);
    fclose(File);
}