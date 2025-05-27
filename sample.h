/*++ ... [ǰ��İ�Ȩ��ע�Ͳ��ֱ��ֲ���] ... --*/

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

// ÿ���ͻ������ӵĽڵ�
typedef struct _CLIENT_NODE {
    uint32_t times; // ͨ�Ŵ���
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
    struct _SERVER_CONTEXT* ServerContext; // �����������Ľṹ��
} CHAT_CONTEXT;

/**
 * ��ӡʹ�ð�����Ϣ��
 *
 * �˺���չʾ�����ʹ�� quicsample �����Կͻ��ˡ���ͻ��˻������ģʽ���С�
 * �������Ƿ�������Ԥ�������������Ƿ���ʾ��ͻ�����صİ�����Ϣ��
 **/
void PrintUsage()
{
    printf(
        "\n"
        "QUICProject ����һ���򵥵Ŀͻ��˻��������\n"
        "\n"
        "�÷�:\n"
        "\n"
        // ���ͻ���ģʽ
        "  QUICProject.exe -client -unsecure -name:{Username} -target:{IPAddress|Hostname} [-ticket:<ticket>]\n"
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
        // ��ͻ���ģʽ������������Ԥ������ʱ��ʾ��
        "  QUICProject.exe -multiclient -count:<N> -unsecure -target:{IPAddress|Hostname}\n"
#endif
        // ������ģʽ��������֤��ʽ��֤���ϣ���ļ�·����
        "  QUICProject.exe -server -cert_hash:<...>\n"
        "  QUICProject.exe -server -cert_file:<...> -key_file:<...> [-password:<...>]\n"
        "\n"
        // ����˵�����Խ�һ�����������
        "����˵��:\n"
        "  -client: �����ͻ���ģʽ��\n"
        "  -multiclient: ������ͻ���ģʽ����Ҫ����Ԥ�����ܣ���\n"
        "  -server: ����������ģʽ��\n"
        "  -unsecure: �ڿͻ���ģʽ�½���֤����֤��\n"
        "  -name: �ڿͻ���ģʽ�������û�����\n"
        "  -target: ָ��Ŀ��������� IP ��ַ����������\n"
        "  -ticket: ����ѡ���ṩ�Ự�ָ�Ʊ�ݡ�\n"
        "  -count: �ڶ�ͻ���ģʽ��ָ��Ҫ��������������\n"
        "  -cert_hash: �ڷ�����ģʽ��ʹ��֤���ϣ���������֤��\n"
        "  -cert_file: �ڷ�����ģʽ��ʹ��֤���ļ�·�����������֤��\n"
        "  -key_file: �ڷ�����ģʽ��ָ��˽Կ�ļ�·����\n"
        "  -password: ����ѡ�����˽Կ�ļ������뱣�������ṩ�����롣\n"
    );
}

// ����Ƿ����ָ����־
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

// ��ȡָ��������ֵ
_Ret_maybenull_  // �����ú������ܷ���һ����ָ�루NULL����
_Null_terminated_ // ����ֵ��һ���Կ��ַ���'\0'����β���ַ���
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

// ����ʮ�������ַ�
uint8_t DecodeHexChar(
    _In_ char c
)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return 0;
}

// ����ʮ�����ƻ�����
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

// ���뻺����Ϊʮ�������ַ���
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

// д��SSL��Կ��־�ļ�
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