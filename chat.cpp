#include "sample.h"

using namespace std;

// 创建聊天上下文
CHAT_CONTEXT* ChatContext = (CHAT_CONTEXT*)malloc(sizeof(CHAT_CONTEXT));

// 将新的客户端信息，写入服务器上下文中
void AddClientToServer(SERVER_CONTEXT* server, HQUIC stream) {
    std::lock_guard<std::mutex> lock(server->lock_);  // 自动加锁，离开作用域自动解锁
    auto client_node = std::make_shared<CLIENT_NODE>();
    client_node->Stream = stream;
    client_node->times = 0;
    server->client_list_.push_back(client_node);
}

// 删除指定客户端信息
void RemoveClientFromServer(SERVER_CONTEXT* server, HQUIC stream) {
    std::lock_guard<std::mutex> lock(server->lock_);

    // 使用 std::list::remove_if 进行条件删除
    server->client_list_.remove_if(
        [stream](const std::shared_ptr<CLIENT_NODE>& client) {
            return client->Stream == stream;
        }
    );
}

// 发送消息函数
void SendMessage(_In_ HQUIC Stream, _In_ const char* Message) {
    QUIC_STATUS Status;
    uint32_t MessageLength = (uint32_t)strlen(Message);
    std::string new_message = std::string(Message);
    /*if (ChatContext->IsServer) {
        MessageLength += (uint32_t)strlen("[Server]:");
        new_message = "[Server]:" + new_message;
    }*/
    
    // 分配内存用于发送缓冲区
    void* SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + MessageLength);
    if (SendBufferRaw == NULL) {
        printf("SendBuffer allocation failed!\n");
        return;
    }

    QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = MessageLength;
    memcpy(SendBuffer->Buffer, new_message.c_str(), MessageLength);

    //printf("[strm][%p] Sending: %s\n", Stream, Message);

    if (QUIC_FAILED(Status = MsQuic->StreamSend(
        Stream,
        SendBuffer,
        1,
        QUIC_SEND_FLAG_NONE,  // 不关闭流
        SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
    }
}

// 服务器广播函数
void BroadcastMessage(SERVER_CONTEXT* server, const char* message) {
    std::lock_guard<std::mutex> lock(server->lock_); // 自动加锁解锁
    for (const auto& client : server->client_list_) {
        SendMessage(client->Stream, message);
    }
}

// 流回调函数（客户端和服务端共用）
QUIC_STATUS QUIC_API ChatStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
) {
    //CHAT_CONTEXT* ChatContext = (CHAT_CONTEXT*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        free(Event->SEND_COMPLETE.ClientContext);
        //printf("[strm][%p] Send complete\n", Stream);
        break;

    case QUIC_STREAM_EVENT_RECEIVE:
        //printf("[strm][%p] Received: ", Stream);
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            // 确保以null结尾
            uint8_t* buffer = Event->RECEIVE.Buffers[i].Buffer;
            uint32_t length = Event->RECEIVE.Buffers[i].Length;
            char* temp = (char*)malloc(length + 1);
            if (temp) {
                memcpy(temp, buffer, length);
                temp[length] = '\0';
                printf("%s", temp);
           
            }
            printf("\n");
            if (ChatContext->IsServer) {
                BroadcastMessage(ChatContext->ServerContext, temp);
                cout << "[strm][all stream] Broadcast Message Successfully" << endl;
                
            }
            free(temp);
        }
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        printf("[strm][%p] Peer shutdown\n", Stream);
        if (ChatContext->IsServer) {
            SendMessage(Stream, "Goodbye from server!");
        }
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        printf("[strm][%p] Stream closed\n", Stream);
        if (ChatContext->IsServer) {
            RemoveClientFromServer(ChatContext->ServerContext, Stream);
        }
        
        MsQuic->StreamClose(Stream);
        if (ChatContext) {
            free(ChatContext);
        }
        break;

    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

// 服务端连接回调
QUIC_STATUS QUIC_API ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
) {
    UNREFERENCED_PARAMETER(Context);

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Client connected\n", Connection);
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        printf("[strm][%p] Client started stream\n", Event->PEER_STREAM_STARTED.Stream);
        // 将客户端流添加到服务端的上下文中
        AddClientToServer(ChatContext->ServerContext, Event->PEER_STREAM_STARTED.Stream);
        MsQuic->SetCallbackHandler(
            Event->PEER_STREAM_STARTED.Stream,
            (void*)ChatStreamCallback,
            ChatContext);

        break;
    }

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Connection closed\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;

    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

// 表示该函数只能在 PASSIVE_LEVEL 的 IRQL（中断请求级别）下调用，这是 Windows 内核中最低优先级的执行级别，通常用于处理非实时任务
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
/*
这个函数是一个 监听器回调函数，它的主要作用是：
在有新的客户端连接到来时（QUIC_LISTENER_EVENT_NEW_CONNECTION），
设置该连接的回调函数为 ServerConnectionCallback
并为其应用一个预先配置好的 QUIC 配置（包括安全设置、协议参数等）
*/
QUIC_STATUS QUIC_API ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
)
{
    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(Context);
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
        break;
    default:
        break;
    }
    return Status;
}

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    // 核心凭据配置结构体，包含了如证书加载方式、验证模式（服务器/客户端）、ALPN列表等信息。
    QUIC_CREDENTIAL_CONFIG CredConfig;
    // 联合体用于提供多种不同的证书配置方式，但请注意，在任意时刻只能使用其中一种字段。
    union {
        // 使用证书的SHA-1哈希值从本地证书存储中加载证书。常用于Windows系统中已安装的证书。
        QUIC_CERTIFICATE_HASH CertHash;
        // 类似于CertHash，但允许指定证书存储位置（例如“本地计算机”或“当前用户”）。
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        // 从文件系统中加载PEM或DER格式的证书文件（不带密码保护）。
        QUIC_CERTIFICATE_FILE CertFile;
        // 从受密码保护的PFX或PEM文件中加载证书。
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

/**
 * 根据命令行参数加载 QUIC 服务器配置和凭据。
 *
 * 支持两种证书加载方式：
 * - cert_hash: 使用证书哈希（Windows 系统证书存储）
 * - cert_file + key_file: 使用 PEM 或 PFX 文件（可选密码保护）
 */
BOOLEAN ServerLoadConfiguration(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
)
{
    // 初始化 QUIC_SETTINGS 结构体，并设置一些基本服务器配置
    QUIC_SETTINGS Settings = { 0 };

    // 设置连接空闲超时时间（单位：毫秒）
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    // 设置服务器支持会话恢复和 0-RTT
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;

    // 设置允许客户端打开的双向流数量为 1
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    // 定义一个凭证配置辅助结构体，用于灵活地设置不同类型的证书
    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config)); // 清零初始化

    // 设置默认凭证标志为无
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    // 获取证书相关参数
    const char* Cert;
    const char* KeyFile;

    // 尝试从命令行获取 cert_hash 参数（使用证书哈希）
    if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
        // 解码 hex 形式的证书哈希值到 CertHash.ShaHash 缓冲区
        uint32_t CertHashLen =
            DecodeHexBuffer(
                Cert,
                sizeof(Config.CertHash.ShaHash),
                Config.CertHash.ShaHash);

        // 检查解码长度是否符合预期（SHA-1 哈希应为 20 字节）
        if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
            return FALSE;
        }

        // 设置凭据类型为证书哈希
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;

        // 指向联合体中的 CertHash 成员
        Config.CredConfig.CertificateHash = &Config.CertHash;
    }
    // 尝试从命令行获取 cert_file 和 key_file 参数（使用文件路径）
    else if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
        (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {

        // 获取可选的私钥密码
        const char* Password = GetValue(argc, argv, "password");

        if (Password != NULL) {
            // 如果提供了密码，使用受保护的证书文件结构体
            Config.CertFileProtected.CertificateFile = (char*)Cert;
            Config.CertFileProtected.PrivateKeyFile = (char*)KeyFile;
            Config.CertFileProtected.PrivateKeyPassword = (char*)Password;

            // 设置凭据类型为受密码保护的证书文件
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
            Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
        }
        else {
            // 如果没有提供密码，使用不带密码保护的证书文件结构体
            Config.CertFile.CertificateFile = (char*)Cert;
            Config.CertFile.PrivateKeyFile = (char*)KeyFile;

            // 设置凭据类型为普通证书文件
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            Config.CredConfig.CertificateFile = &Config.CertFile;
        }
    }
    else {
        // 如果没有指定任何有效的证书参数，打印错误并返回失败
        printf("Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and optionally 'password')]!\n");
        return FALSE;
    }
    // 打开 QUIC 配置对象
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
        Registration,          // 注册句柄
        &Alpn,                 // ALPN 协议名称
        1,                     // ALPN 数量
        &Settings,             // 配置设置
        sizeof(Settings),      // 设置大小
        NULL,                  // 可选上下文
        &Configuration)))      // 输出配置句柄
    {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }
    // 加载证书凭据到 QUIC 配置中
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &Config.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }
    return TRUE;
}

// 服务器端运行函数
void RunServer(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
) {
    QUIC_STATUS Status;
    HQUIC Listener = NULL;
    QUIC_ADDR Address = { 0 };

    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);

    ChatContext->name = "Server";
    ChatContext->Stream = NULL;
    ChatContext->IsServer = true;
    ChatContext->ServerContext = new SERVER_CONTEXT;

    if (!ServerLoadConfiguration(argc, argv)) {
        return;
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, NULL, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("Server running. Press Enter to stop...\n");
    getchar();

Error:
    if (Listener != NULL) {
        MsQuic->ListenerClose(Listener);
    }
}

// 客户端连接回调
QUIC_STATUS QUIC_API ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
) {
    /*CHAT_CONTEXT* ChatContext = (CHAT_CONTEXT*)Context;*/

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED: {
        printf("[conn][%p] Connected to server\n", Connection);

        // 创建流
        HQUIC Stream;
        if (QUIC_FAILED(MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE,
            ChatStreamCallback, ChatContext, &Stream))) {
            printf("Failed to open stream\n");
            break;
        }

        if (QUIC_FAILED(MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
            printf("Failed to start stream\n");
            MsQuic->StreamClose(Stream);
            break;
        }
        ChatContext->Stream = Stream;
        SendMessage(Stream, ChatContext->name);
        break;
    }

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Disconnected\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;

    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

/**
 * 加载客户端配置和凭据。
 *
 * 参数：
 * - Unsecure: 如果为 TRUE，则禁用证书验证（仅用于测试环境）
 *
 * 步骤：
 * - 初始化 QUIC 设置结构体
 * - 根据是否安全连接设置凭证配置
 * - 打开并加载配置到 MsQuic 库中
 */
BOOLEAN ClientLoadConfiguration(
    BOOLEAN Unsecure  // 是否启用不安全模式（跳过证书验证）
)
{
    QUIC_STATUS Status;

    // 初始化 QUIC 设置结构体，并设置空闲超时时间
    QUIC_SETTINGS Settings = { 0 };
    Settings.IdleTimeoutMs = IdleTimeoutMs;  // 空闲超时时间（毫秒）
    Settings.IsSet.IdleTimeoutMs = TRUE;     // 标记已设置空闲超时

    // 初始化凭证配置结构体
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));  // 清零初始化
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE; // 客户端不需要提供证书
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT; // 标记为客户端凭证

    // 如果启用了不安全模式，则禁用证书验证
    if (Unsecure) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    // 打开 QUIC 配置对象
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
        Registration,          // 注册句柄
        &Alpn,                 // ALPN 协议名称
        1,                     // ALPN 数量
        &Settings,             // 配置设置
        sizeof(Settings),      // 设置大小
        NULL,                  // 可选上下文
        &Configuration)))      // 输出配置句柄
    {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    // 加载凭证配置到 QUIC 配置中
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;  // 成功加载配置和凭证
}

// 客户端运行函数
void RunClient(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
) {
    if (!ClientLoadConfiguration(GetFlag(argc, argv, "unsecure"))) {
        return;
    }

    QUIC_STATUS Status;
    const char* Target;
    HQUIC Connection = NULL;
    
    if ((Target = GetValue(argc, argv, "target")) == NULL) {
        printf("Must specify '-target' argument!\n");
        goto Error;
    }
    
    if (!ChatContext) {
        printf("Failed to allocate chat context\n");
        goto Error;
    }

    ChatContext->name = GetValue(argc, argv, "name");
    ChatContext->Stream = NULL;
    ChatContext->IsServer = false;
    ChatContext->ServerContext = NULL;

    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, ChatContext, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        free(ChatContext);
        goto Error;
    }

    printf("[conn][%p] Connecting to %s...\n", Connection, Target);

    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration,
        QUIC_ADDRESS_FAMILY_UNSPEC, Target, UdpPort))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        free(ChatContext);
        goto Error;
    }

    // 主聊天循环
    char InputBuffer[SendBufferLength];
    while (true) {
        if (fgets(InputBuffer, sizeof(InputBuffer), stdin) == NULL) {
            break;
        }

        // 移除换行符
        InputBuffer[strcspn(InputBuffer, "\n")] = '\0';

        if (strcmp(InputBuffer, "exit") == 0) {
            if (ChatContext->Stream) {
                SendMessage(ChatContext->Stream, "Client is exiting");
                MsQuic->StreamShutdown(ChatContext->Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
            }
            break;
        }

        if (ChatContext->Stream) {
            std::string message = "[" + std::string(ChatContext->name) + "]:" + InputBuffer;
            SendMessage(ChatContext->Stream, message.c_str());
        }
        else {
            printf("Stream not ready yet. Waiting for connection...\n");
        }
    }

Error:
    if (Connection != NULL) {
        MsQuic->ConnectionClose(Connection);
    }
}

// 主函数
int QUIC_MAIN_EXPORT main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
) {
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
        PrintUsage();
    }
    else if (GetFlag(argc, argv, "client")) {
        RunClient(argc, argv);
    }
    else if (GetFlag(argc, argv, "server")) {
        RunServer(argc, argv);
    }
    else {
        PrintUsage();
    }

Error:
    if (MsQuic != NULL) {
        if (Configuration != NULL) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != NULL) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return (int)Status;
}