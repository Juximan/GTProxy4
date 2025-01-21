#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#ifdef _WIN32
    #include <winsock2.h>
    #define socklen_t int
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netdb.h>
#endif
#include <string.h>
#include <unistd.h>

#include "httpService.h"
#include "tlse/tlse.h"
#include "utils/utils.h"
#include "proxyStruct.h"

const unsigned char* certPem = "-----BEGIN CERTIFICATE-----\n\
MIIFHDCCAwQCFAiN1SGWV6ORqkLB3Y2NxzQh/zq2MA0GCSqGSIb3DQEBCwUAMHgx
CzAJBgNVBAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazERMA8GA1UEBwwIQnJvb2ts
eW4xEjAQBgNVBAoMCUludmlzaWJsZTESMBAGA1UECwwJSW52aXNpYmxlMRswGQYD
VQQDDBJ3d3cuZ3Jvd3RvcGlhMS5jb20wHhcNMjIwOTA4MTM1MjMxWhcNMzIwOTA1
MTM1MjMxWjAdMRswGQYDVQQDDBJ3d3cuZ3Jvd3RvcGlhMS5jb20wggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQCKRK4Ff7RkJ+1IpZWlsLjxZWL3aX0ySiON
W604PsDi74cNNpLB7PbcFP3o0HieVf2n99+l3jUaVxYQYxAJ3BKtXrTdQ/UWvoYU
OZowIqnn2NEz7tUh/AxfqkN88z5OQz4MrwSEZ+Oh7hQwGwaFmLazFElwgI6gD8eo
pLA8fiRk+XKS6dhKs8tR4mDJe1yot67cW5vW6nOGuMyiaDlx6FkeNPjlyQ7BvLjG
Vt9XDyi1xPBmkPI+GXfAdtGKA7bOhmsvCbh/1gcXKOBeCSk3BpW9ZRnxr9M8lbZt
lfsu3xX/AbX2g0Z+k3ABnCVcdV01uSZKUKsIzX1r50HmEo3BTn9Og2wYB6AY5YWT
yGKTAz9V2szjMi/+395iaMLtk2+24/Q6eTCd6vPv8ijwmqNm429VLC2cvhDK2ll3
sGMu+k7ragm7lLp0ydkaxvUi6IkWMoPks6r9TTwPgfwMuaSN9sb3uz5TlLivOYb1
088nnMvcXsZ2GA9aBM6R6t8moXcEBobxip7xXQFKNa/w1nUX/d8Z3H9PTUuYwFvY
8WOZqqSh2hyCFYFvzcSf0jZ9VM5cZxLNJDmrzNo3MCKcAo0KJlzlIDGpkbdevXXC
NGPoSWlTymwLQZ7F6L9QbJGynLo50gmMGZqz9pLlGRDXqSWEzWciPIbpBhWTCjgl
xsHiVhtvRQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQB4vZYNRrUQ/A1gUbjW3AcI
0agUPotMx4pcwiZrdXyMant7iSaEXkRiywQLfAtlIzK/Q1IqTTkpWyz5NQGxc6t9
n3OKWsNjHeJxZbzpp1b1W92bDTcSl7lYoTS5tPF9LUEon+QmnfJaWVS7m+0M87VH
4q657UMNRXnAzGzNrNrsgQ7xlgJ8btqqJgDYnDTQB1LuUq4jPw6UTAsOYGK9ZoQD
3wHGosdgVqeQo0y44sMmXh6tAQmN2pP/DTPqE8ML6jfqw3i5QJrKxVPKm9Vxpw67
R8m3ABgDU1Yiab+I/eGycFs9iMEa+GuXOjh7251EBivNF2XnMXlEWmTAtl3zgM7y
raG3NGW3EP/eMHA2YjZ6+DsQzPY8xU8cuIxt9gkaNWROKBPolUc5OPMjzjcVftJ3
7GbLPS8LOswW6mbsjInwO6r/kxH111WLXYx843CJqPRwb2QgoHUMjTdMzzQhKBPK
QnDRhBHOkbvuFSxhSt4nYEAGzmgvHzLhlsuAvrYzQ2fo7W/LPcusr14zTscF6tNF
BOypjIFopMCc+joqoTwe55+xZmLrCEAHO99NbI8ZpldRy068tnYBp4vDycf/T7AB
zjT7/9VlHlaVtuXbhzaTCp0q8DWxKar5nUWUcXsEEImprHI9uq8WPqFI7OPb+vyI
bNORBaKydcOoQGUrBjHF7g==\n\
-----END CERTIFICATE-----";

const unsigned char* keyPem = "-----BEGIN PRIVATE KEY-----\n\
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
2QQagF6gXY9YhoPIYpzzqHW8PLz3kBU=\n\
-----END PRIVATE KEY-----";

int send_pending(int client_sock, struct TLSContext *context) {
    unsigned int out_buffer_len = 0;
    const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    unsigned int out_buffer_index = 0;
    int send_res = 0;
    while ((out_buffer) && (out_buffer_len > 0)) {
        int res = send(client_sock, (char *)&out_buffer[out_buffer_index], out_buffer_len, 0);
        if (res <= 0) {
            send_res = res;
            break;
        }
        out_buffer_len -= res;
        out_buffer_index += res;
    }
    tls_buffer_clear(context);
    return send_res;
}

struct HTTPInfo HTTPSClient(const char* website) {
    unsigned char read_buffer[0xFFFF];
    unsigned char client_message[0xFFFF];

    int sockfd, portno = 8080;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    struct HTTPInfo info;

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("[HTTPService Client] Error: opening socket\n");
        exit(0);
    }

    server = gethostbyname(website);
    if (server == NULL) {
        printf("[HTTPService Client] Error: no such host\n");
        exit(0);
    }
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
        printf("[HTTPService Client] Error: connecting\n");
        exit(0);
    }

    struct TLSContext *context = tls_create_context(0, TLS_V12);

    tls_make_exportable(context, 1);
    tls_client_connect(context);
    send_pending(sockfd, context);

    int read_size;
    while ((read_size = recv(sockfd, client_message, sizeof(client_message), 0)) > 0) {
        tls_consume_stream(context, client_message, read_size, NULL);
        send_pending(sockfd, context);
        if (tls_established(context)) {
            const char *request = "POST /growtopia/server_data.php HTTP/1.1\r\nUser-Agent: UbiServices_SDK_2022.Release.9_PC64_unicode_static\r\nHost: www.growtopia1.com\r\nAccept: */*\r\nConnection: close\r\ncontent-length: 0\r\n\r\n";
            if (!tls_make_ktls(context, sockfd)) send(sockfd, request, strlen(request), 0);
            else {
                tls_write(context, (unsigned char *)request, strlen(request));
                send_pending(sockfd, context);
            }
            int tempLen = tls_read(context, read_buffer, 0xFFFF - 1);
            if (tempLen != 0) info.bufferLen = tempLen;
        }
    }
    read_buffer[info.bufferLen] = '\0';
    info.buffer = read_buffer;
    SSL_CTX_free(context);
    return info;
}

void* HTTPSServer(void* unused) {
    int socket_desc, client_sock;
    socklen_t c;
    struct sockaddr_in server, client;
    const char msg[] = "HTTP/1.1 200 OK\r\nContent-length: 279\r\n\r\nserver|127.0.0.1\nport|17091\ntype|1\n#maint|maintenance\nbeta_server|beta.growtopiagame.com\nbeta_port|26999\nbeta_type|1\nbeta2_server|beta2.growtopiagame.com\nbeta2_port|26999\nbeta2_type|1\nbeta3_server|34.202.7.77\nbeta3_port|26999\nbeta3_type|1\ntype2|0\nmeta|localhost\nRTENDMARKERBS1001";

    #ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    #endif

    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        printf("[HTTPService Server] Error: Could not create socket\n");
        exit(0);
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(userConfig.httpsPort);

    int enable = 1;
    setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &enable, 4);

    if (bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0) {
        printf("[HTTPService Server] Error: bind failed! If you are not a root user, please change it to 8080\n");
        exit(1);
    }

    listen(socket_desc, 3);

    c = sizeof(struct sockaddr_in);

    SSL* server_ctx = SSL_CTX_new(SSLv3_server_method());

    if (!server_ctx) {
        printf("[HTTPService Server] Error: creating server context");
        exit(-1);
    }

    tls_load_certificates(server_ctx, certPem, strlen(certPem));
    tls_load_private_key(server_ctx, keyPem, strlen(keyPem));

    if (!SSL_CTX_check_private_key(server_ctx)) {
        printf("[HTTPService Server] Error: Private key not loaded\n");
        exit(-2);
    }

    printf("[HTTPService Server] Log: HTTPS Server is enabled\n");

    while(1) {
        client_sock = accept(socket_desc, (struct sockaddr*)&client, &c);

        if (client_sock < 0) {
            printf("[HTTPService Server] Error: Accept failed\n");
            exit(-3);
        }

        SSL* client = SSL_new(server_ctx);
        if (!client) {
            printf("[HTTPService Server] Error: Error creating SSL Client");
            exit(-4);
        }

        SSL_set_fd(client, client_sock);

        if (SSL_accept(client)) {
            if (SSL_write(client, msg, strlen(msg)) < 0) printf("[HTTPService Server] Error: in SSL Write\n");
        } else printf("[HTTPService Server] Error: in handshake\n");
        SSL_shutdown(client);
        #ifdef _WIN32
        Sleep(500);
        #else
        usleep(500);
        #endif
#ifdef __WIN32
        shutdown(client_sock, SD_BOTH);
        closesocket(client_sock);
#else
        shutdown(client_sock, SHUT_RDWR);
        close(client_sock);
#endif
        SSL_free(client);
    }
    SSL_CTX_free(server_ctx);
}
