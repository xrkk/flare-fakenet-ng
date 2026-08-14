#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#ifdef TARGET_CLIENT
#define CLIENT_ROLE "target"
#else
#define CLIENT_ROLE "non-target"
#endif

static CRITICAL_SECTION output_lock;

static void print_wide_json(const wchar_t *value) {
    int bytes = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
    char *utf8 = bytes > 0 ? (char *)calloc((size_t)bytes, 1) : NULL;
    if (!utf8 || !WideCharToMultiByte(
            CP_UTF8, 0, value, -1, utf8, bytes, NULL, NULL)) {
        printf("<path-conversion-failed>");
        free(utf8);
        return;
    }
    for (const unsigned char *cursor = (unsigned char *)utf8; *cursor; ++cursor) {
        if (*cursor == '\\' || *cursor == '"') putchar('\\');
        if (*cursor >= 0x20) putchar(*cursor);
    }
    free(utf8);
}

static void print_identity(void) {
    wchar_t module[MAX_PATH * 4] = {0};
    wchar_t final_path[32768] = {0};
    DWORD module_len = GetModuleFileNameW(NULL, module, ARRAYSIZE(module));
    HANDLE file = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    FILETIME created, exited, kernel, user;
    ULARGE_INTEGER created_value;
    ULARGE_INTEGER file_id;
    DWORD final_len = 0;
    ZeroMemory(&info, sizeof(info));
    ZeroMemory(&created, sizeof(created));
    if (module_len) {
        file = CreateFileW(module, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);
    }
    if (file != INVALID_HANDLE_VALUE) {
        GetFileInformationByHandle(file, &info);
        final_len = GetFinalPathNameByHandleW(
            file, final_path, ARRAYSIZE(final_path), 0);
    }
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) {
        ZeroMemory(&created, sizeof(created));
    }
    created_value.LowPart = created.dwLowDateTime;
    created_value.HighPart = created.dwHighDateTime;
    file_id.LowPart = info.nFileIndexLow;
    file_id.HighPart = info.nFileIndexHigh;
    printf("{\"event\":\"identity\",\"role\":\"%s\",\"pid\":%lu,"
           "\"creation_time\":%llu,\"volume_serial\":%lu,\"file_id\":%llu,"
           "\"final_path\":\"", CLIENT_ROLE, GetCurrentProcessId(),
           (unsigned long long)created_value.QuadPart,
           (unsigned long)info.dwVolumeSerialNumber,
           (unsigned long long)file_id.QuadPart);
    print_wide_json((final_len && final_len < ARRAYSIZE(final_path)) ?
                    final_path : module);
    printf("\"}\n");
    fflush(stdout);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
}

static unsigned long long epoch_ms_now(void) {
    FILETIME ft;
    ULARGE_INTEGER li;
    GetSystemTimeAsFileTime(&ft);
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    /* FILETIME is 100ns ticks since 1601-01-01; convert to Unix epoch ms. */
    return (li.QuadPart / 10000ULL) - 11644473600000ULL;
}

static void format_endpoint(const struct sockaddr_in *address,
                            char *output, size_t output_size) {
    char ip[INET_ADDRSTRLEN] = {0};
    InetNtopA(AF_INET, (void *)&address->sin_addr, ip, sizeof(ip));
    _snprintf_s(output, output_size, _TRUNCATE, "%s:%u",
                ip, (unsigned)ntohs(address->sin_port));
}

static int run_connection(const char *host, unsigned short port,
                          unsigned index, const char *nonce_prefix) {
    SOCKET client = INVALID_SOCKET;
    struct sockaddr_in remote;
    struct sockaddr_in local_seen;
    struct sockaddr_in peer_seen;
    int endpoint_len;
    DWORD timeout_ms = 5000;
    char nonce[160];
    char request[256];
    char expected[256];
    char response[256] = {0};
    char local_text[64] = {0};
    char peer_text[64] = {0};
    int received = 0;
    int result = 1;
    int winsock_error = 0;
    const char *failure_stage = "invalid_host";
    unsigned long long epoch_ms = 0;

    _snprintf_s(nonce, sizeof(nonce), _TRUNCATE, "%s-%lu-%u",
                nonce_prefix, GetCurrentProcessId(), index);
    _snprintf_s(request, sizeof(request), _TRUNCATE,
                "FNPR/1|%s|%s\n", nonce, CLIENT_ROLE);
    _snprintf_s(expected, sizeof(expected), _TRUNCATE,
                "FNPR/1|%s|OK\n", nonce);
    ZeroMemory(&remote, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    if (InetPtonA(AF_INET, host, &remote.sin_addr) != 1) goto done;
    failure_stage = "socket";
    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) goto done;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&timeout_ms, sizeof(timeout_ms));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
               (const char *)&timeout_ms, sizeof(timeout_ms));
    epoch_ms = epoch_ms_now();
    failure_stage = "connect";
    if (connect(client, (struct sockaddr *)&remote, sizeof(remote)) != 0) goto done;
    failure_stage = "getsockname";
    endpoint_len = sizeof(local_seen);
    if (getsockname(client, (struct sockaddr *)&local_seen, &endpoint_len) != 0)
        goto done;
    failure_stage = "getpeername";
    endpoint_len = sizeof(peer_seen);
    if (getpeername(client, (struct sockaddr *)&peer_seen, &endpoint_len) != 0)
        goto done;
    format_endpoint(&local_seen, local_text, sizeof(local_text));
    format_endpoint(&peer_seen, peer_text, sizeof(peer_text));
    failure_stage = "send";
    if (send(client, request, (int)strlen(request), 0) != (int)strlen(request))
        goto done;
    failure_stage = "recv";
    while (received < (int)sizeof(response) - 1) {
        int count = recv(client, response + received,
                         (int)sizeof(response) - 1 - received, 0);
        if (count < 0) goto done;
        if (count == 0) {
            failure_stage = "recv_eof";
            goto done;
        }
        received += count;
        response[received] = 0;
        if (strchr(response, '\n')) break;
    }
    failure_stage = "response_mismatch";
    if (strcmp(response, expected) != 0) goto done;
    result = 0;
    failure_stage = "";

done:
    if (result != 0) winsock_error = WSAGetLastError();
    EnterCriticalSection(&output_lock);
    printf("{\"event\":\"connection\",\"role\":\"%s\",\"index\":%u,"
           "\"success\":%s,\"failure_stage\":\"%s\","
           "\"winsock_error\":%d,\"local\":\"%s\","
           "\"peer\":\"%s\",\"nonce\":\"%s\",\"epoch_ms\":%llu}\n",
           CLIENT_ROLE, index, result == 0 ? "true" : "false",
           failure_stage, result == 0 ? 0 : winsock_error,
           local_text, peer_text, nonce, epoch_ms);
    fflush(stdout);
    LeaveCriticalSection(&output_lock);
    if (client != INVALID_SOCKET) closesocket(client);
    return result;
}

struct thread_context {
    const char *host;
    const char *nonce_prefix;
    unsigned short port;
    unsigned index;
    HANDLE start_event;
    int result;
};

static DWORD WINAPI run_connection_thread(void *parameter) {
    struct thread_context *context = (struct thread_context *)parameter;
    if (WaitForSingleObject(context->start_event, INFINITE) != WAIT_OBJECT_0) {
        context->result = 2;
        return 2;
    }
    context->result = run_connection(
        context->host, context->port, context->index, context->nonce_prefix);
    return (DWORD)context->result;
}

static int run_parallel_connections(const char *host, unsigned short port,
                                    unsigned count, const char *nonce_prefix,
                                    unsigned *failures) {
    HANDLE start_event = NULL;
    HANDLE threads[MAXIMUM_WAIT_OBJECTS] = {0};
    struct thread_context contexts[MAXIMUM_WAIT_OBJECTS];
    unsigned created = 0;
    int result = 1;

    ZeroMemory(contexts, sizeof(contexts));
    start_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!start_event) goto done;
    for (created = 0; created < count; ++created) {
        contexts[created].host = host;
        contexts[created].nonce_prefix = nonce_prefix;
        contexts[created].port = port;
        contexts[created].index = created;
        contexts[created].start_event = start_event;
        contexts[created].result = 2;
        threads[created] = CreateThread(
            NULL, 0, run_connection_thread, &contexts[created], 0, NULL);
        if (!threads[created]) goto done;
    }
    if (!SetEvent(start_event)) goto done;
    if (WaitForMultipleObjects(count, threads, TRUE, INFINITE) !=
            WAIT_OBJECT_0) {
        goto done;
    }
    *failures = 0;
    for (unsigned index = 0; index < count; ++index) {
        if (contexts[index].result != 0 && contexts[index].result != 1) {
            goto done;
        }
        *failures += (unsigned)contexts[index].result;
    }
    result = 0;

done:
    if (result != 0 && start_event) {
        SetEvent(start_event);
        if (created) WaitForMultipleObjects(created, threads, TRUE, INFINITE);
    }
    for (unsigned index = 0; index < created; ++index) {
        if (threads[index]) CloseHandle(threads[index]);
    }
    if (start_event) CloseHandle(start_event);
    return result;
}

int main(int argc, char **argv) {
    const char *host = NULL;
    const char *nonce_prefix = "acceptance";
    unsigned short port = 0;
    unsigned connections = 1;
    unsigned minimum_start_interval_ms = 0;
    unsigned parallel_connections = 0;
    unsigned failures = 0;
    ULONGLONG previous_start_ms = 0;
    ULONGLONG test_start_ms;
    WSADATA data;
    for (int index = 1; index < argc; ++index) {
        if (!strcmp(argv[index], "--host") && index + 1 < argc) host = argv[++index];
        else if (!strcmp(argv[index], "--port") && index + 1 < argc)
            port = (unsigned short)strtoul(argv[++index], NULL, 10);
        else if (!strcmp(argv[index], "--connections") && index + 1 < argc)
            connections = (unsigned)strtoul(argv[++index], NULL, 10);
        else if (!strcmp(argv[index], "--minimum-start-interval-ms") &&
                index + 1 < argc)
            minimum_start_interval_ms =
                (unsigned)strtoul(argv[++index], NULL, 10);
        else if (!strcmp(argv[index], "--parallel-connections") &&
                index + 1 < argc)
            parallel_connections = (unsigned)strtoul(argv[++index], NULL, 10);
        else if (!strcmp(argv[index], "--nonce-prefix") && index + 1 < argc)
            nonce_prefix = argv[++index];
        else {
            fprintf(stderr, "invalid argument\n");
            return 2;
        }
    }
    if (!host || !port || !connections ||
            parallel_connections > MAXIMUM_WAIT_OBJECTS ||
            (parallel_connections && minimum_start_interval_ms) ||
            WSAStartup(MAKEWORD(2, 2), &data) != 0)
        return 2;
    InitializeCriticalSection(&output_lock);
    print_identity();
    test_start_ms = GetTickCount64();
    if (parallel_connections) {
        connections = parallel_connections;
        if (run_parallel_connections(
                host, port, connections, nonce_prefix, &failures) != 0) {
            DeleteCriticalSection(&output_lock);
            WSACleanup();
            return 2;
        }
    } else {
        for (unsigned index = 0; index < connections; ++index) {
            ULONGLONG now = GetTickCount64();
            ULONGLONG elapsed_ms = previous_start_ms ?
                now - previous_start_ms : minimum_start_interval_ms;
            if (minimum_start_interval_ms > elapsed_ms) {
                Sleep((DWORD)(minimum_start_interval_ms - elapsed_ms));
            }
            previous_start_ms = GetTickCount64();
            failures += (unsigned)run_connection(
                host, port, index, nonce_prefix);
        }
    }
    printf("{\"event\":\"summary\",\"role\":\"%s\","
           "\"connections\":%u,\"failures\":%u,\"elapsed_ms\":%llu}\n",
           CLIENT_ROLE, connections, failures,
           (unsigned long long)(GetTickCount64() - test_start_ms));
    fflush(stdout);
    DeleteCriticalSection(&output_lock);
    WSACleanup();
    return failures ? 1 : 0;
}
