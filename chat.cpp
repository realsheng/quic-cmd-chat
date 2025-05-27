#include "sample.h"

using namespace std;

// ��������������
CHAT_CONTEXT* ChatContext = (CHAT_CONTEXT*)malloc(sizeof(CHAT_CONTEXT));

// ���µĿͻ�����Ϣ��д���������������
void AddClientToServer(SERVER_CONTEXT* server, HQUIC stream) {
    std::lock_guard<std::mutex> lock(server->lock_);  // �Զ��������뿪�������Զ�����
    auto client_node = std::make_shared<CLIENT_NODE>();
    client_node->Stream = stream;
    client_node->times = 0;
    server->client_list_.push_back(client_node);
}

// ɾ��ָ���ͻ�����Ϣ
void RemoveClientFromServer(SERVER_CONTEXT* server, HQUIC stream) {
    std::lock_guard<std::mutex> lock(server->lock_);

    // ʹ�� std::list::remove_if ��������ɾ��
    server->client_list_.remove_if(
        [stream](const std::shared_ptr<CLIENT_NODE>& client) {
            return client->Stream == stream;
        }
    );
}

// ������Ϣ����
void SendMessage(_In_ HQUIC Stream, _In_ const char* Message) {
    QUIC_STATUS Status;
    uint32_t MessageLength = (uint32_t)strlen(Message);
    std::string new_message = std::string(Message);
    /*if (ChatContext->IsServer) {
        MessageLength += (uint32_t)strlen("[Server]:");
        new_message = "[Server]:" + new_message;
    }*/
    
    // �����ڴ����ڷ��ͻ�����
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
        QUIC_SEND_FLAG_NONE,  // ���ر���
        SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
    }
}

// �������㲥����
void BroadcastMessage(SERVER_CONTEXT* server, const char* message) {
    std::lock_guard<std::mutex> lock(server->lock_); // �Զ���������
    for (const auto& client : server->client_list_) {
        SendMessage(client->Stream, message);
    }
}

// ���ص��������ͻ��˺ͷ���˹��ã�
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
            // ȷ����null��β
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

// ��������ӻص�
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
        // ���ͻ�������ӵ�����˵���������
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

// ��ʾ�ú���ֻ���� PASSIVE_LEVEL �� IRQL���ж����󼶱��µ��ã����� Windows �ں���������ȼ���ִ�м���ͨ�����ڴ����ʵʱ����
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
/*
���������һ�� �������ص�������������Ҫ�����ǣ�
�����µĿͻ������ӵ���ʱ��QUIC_LISTENER_EVENT_NEW_CONNECTION����
���ø����ӵĻص�����Ϊ ServerConnectionCallback
��Ϊ��Ӧ��һ��Ԥ�����úõ� QUIC ���ã�������ȫ���á�Э������ȣ�
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
    // ����ƾ�����ýṹ�壬��������֤����ط�ʽ����֤ģʽ��������/�ͻ��ˣ���ALPN�б����Ϣ��
    QUIC_CREDENTIAL_CONFIG CredConfig;
    // �����������ṩ���ֲ�ͬ��֤�����÷�ʽ������ע�⣬������ʱ��ֻ��ʹ������һ���ֶΡ�
    union {
        // ʹ��֤���SHA-1��ϣֵ�ӱ���֤��洢�м���֤�顣������Windowsϵͳ���Ѱ�װ��֤�顣
        QUIC_CERTIFICATE_HASH CertHash;
        // ������CertHash��������ָ��֤��洢λ�ã����硰���ؼ�������򡰵�ǰ�û�������
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        // ���ļ�ϵͳ�м���PEM��DER��ʽ��֤���ļ����������뱣������
        QUIC_CERTIFICATE_FILE CertFile;
        // �������뱣����PFX��PEM�ļ��м���֤�顣
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

/**
 * ���������в������� QUIC ���������ú�ƾ�ݡ�
 *
 * ֧������֤����ط�ʽ��
 * - cert_hash: ʹ��֤���ϣ��Windows ϵͳ֤��洢��
 * - cert_file + key_file: ʹ�� PEM �� PFX �ļ�����ѡ���뱣����
 */
BOOLEAN ServerLoadConfiguration(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
)
{
    // ��ʼ�� QUIC_SETTINGS �ṹ�壬������һЩ��������������
    QUIC_SETTINGS Settings = { 0 };

    // �������ӿ��г�ʱʱ�䣨��λ�����룩
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    // ���÷�����֧�ֻỰ�ָ��� 0-RTT
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;

    // ��������ͻ��˴򿪵�˫��������Ϊ 1
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    // ����һ��ƾ֤���ø����ṹ�壬�����������ò�ͬ���͵�֤��
    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config)); // �����ʼ��

    // ����Ĭ��ƾ֤��־Ϊ��
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    // ��ȡ֤����ز���
    const char* Cert;
    const char* KeyFile;

    // ���Դ������л�ȡ cert_hash ������ʹ��֤���ϣ��
    if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
        // ���� hex ��ʽ��֤���ϣֵ�� CertHash.ShaHash ������
        uint32_t CertHashLen =
            DecodeHexBuffer(
                Cert,
                sizeof(Config.CertHash.ShaHash),
                Config.CertHash.ShaHash);

        // �����볤���Ƿ����Ԥ�ڣ�SHA-1 ��ϣӦΪ 20 �ֽڣ�
        if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
            return FALSE;
        }

        // ����ƾ������Ϊ֤���ϣ
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;

        // ָ���������е� CertHash ��Ա
        Config.CredConfig.CertificateHash = &Config.CertHash;
    }
    // ���Դ������л�ȡ cert_file �� key_file ������ʹ���ļ�·����
    else if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
        (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {

        // ��ȡ��ѡ��˽Կ����
        const char* Password = GetValue(argc, argv, "password");

        if (Password != NULL) {
            // ����ṩ�����룬ʹ���ܱ�����֤���ļ��ṹ��
            Config.CertFileProtected.CertificateFile = (char*)Cert;
            Config.CertFileProtected.PrivateKeyFile = (char*)KeyFile;
            Config.CertFileProtected.PrivateKeyPassword = (char*)Password;

            // ����ƾ������Ϊ�����뱣����֤���ļ�
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
            Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
        }
        else {
            // ���û���ṩ���룬ʹ�ò������뱣����֤���ļ��ṹ��
            Config.CertFile.CertificateFile = (char*)Cert;
            Config.CertFile.PrivateKeyFile = (char*)KeyFile;

            // ����ƾ������Ϊ��֤ͨ���ļ�
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            Config.CredConfig.CertificateFile = &Config.CertFile;
        }
    }
    else {
        // ���û��ָ���κ���Ч��֤���������ӡ���󲢷���ʧ��
        printf("Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and optionally 'password')]!\n");
        return FALSE;
    }
    // �� QUIC ���ö���
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
        Registration,          // ע����
        &Alpn,                 // ALPN Э������
        1,                     // ALPN ����
        &Settings,             // ��������
        sizeof(Settings),      // ���ô�С
        NULL,                  // ��ѡ������
        &Configuration)))      // ������þ��
    {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }
    // ����֤��ƾ�ݵ� QUIC ������
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &Config.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }
    return TRUE;
}

// �����������к���
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

// �ͻ������ӻص�
QUIC_STATUS QUIC_API ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
) {
    /*CHAT_CONTEXT* ChatContext = (CHAT_CONTEXT*)Context;*/

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED: {
        printf("[conn][%p] Connected to server\n", Connection);

        // ������
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
 * ���ؿͻ������ú�ƾ�ݡ�
 *
 * ������
 * - Unsecure: ���Ϊ TRUE�������֤����֤�������ڲ��Ի�����
 *
 * ���裺
 * - ��ʼ�� QUIC ���ýṹ��
 * - �����Ƿ�ȫ��������ƾ֤����
 * - �򿪲��������õ� MsQuic ����
 */
BOOLEAN ClientLoadConfiguration(
    BOOLEAN Unsecure  // �Ƿ����ò���ȫģʽ������֤����֤��
)
{
    QUIC_STATUS Status;

    // ��ʼ�� QUIC ���ýṹ�壬�����ÿ��г�ʱʱ��
    QUIC_SETTINGS Settings = { 0 };
    Settings.IdleTimeoutMs = IdleTimeoutMs;  // ���г�ʱʱ�䣨���룩
    Settings.IsSet.IdleTimeoutMs = TRUE;     // ��������ÿ��г�ʱ

    // ��ʼ��ƾ֤���ýṹ��
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));  // �����ʼ��
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE; // �ͻ��˲���Ҫ�ṩ֤��
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT; // ���Ϊ�ͻ���ƾ֤

    // ��������˲���ȫģʽ�������֤����֤
    if (Unsecure) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    // �� QUIC ���ö���
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
        Registration,          // ע����
        &Alpn,                 // ALPN Э������
        1,                     // ALPN ����
        &Settings,             // ��������
        sizeof(Settings),      // ���ô�С
        NULL,                  // ��ѡ������
        &Configuration)))      // ������þ��
    {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    // ����ƾ֤���õ� QUIC ������
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;  // �ɹ��������ú�ƾ֤
}

// �ͻ������к���
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

    // ������ѭ��
    char InputBuffer[SendBufferLength];
    while (true) {
        if (fgets(InputBuffer, sizeof(InputBuffer), stdin) == NULL) {
            break;
        }

        // �Ƴ����з�
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

// ������
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