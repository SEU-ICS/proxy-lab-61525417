#include "csapp.h"

#include <stdint.h>
#include <strings.h>

#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400
#define MAX_HEADER_SIZE 65536
#define MAX_HOST_SIZE 1024
#define MAX_PORT_SIZE 6
#define MAX_CACHE_KEY (MAXLINE + MAX_HOST_SIZE + MAX_PORT_SIZE + 16)

static const char *user_agent_hdr =
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) "
    "Gecko/20120305 Firefox/10.0.3\r\n";

typedef struct cache_entry {
    char *key;
    unsigned char *data;
    size_t size;
    uint64_t last_used;
    struct cache_entry *next;
} cache_entry_t;

static cache_entry_t *cache_head;
static size_t cache_size;
static uint64_t cache_clock;
static pthread_rwlock_t cache_lock = PTHREAD_RWLOCK_INITIALIZER;

static void *worker(void *arg);
static void serve_client(int clientfd);
static int read_request_headers(rio_t *rio, char *host_header,
                                size_t host_capacity, char *other_headers,
                                size_t other_capacity);
static int parse_absolute_uri(const char *uri, char *hostname,
                              size_t hostname_capacity, char *port,
                              size_t port_capacity, char *path,
                              size_t path_capacity, char *generated_host,
                              size_t generated_host_capacity);
static int parse_authority(const char *authority, char *hostname,
                           size_t hostname_capacity, char *port,
                           size_t port_capacity, char *formatted_host,
                           size_t formatted_host_capacity);
static int make_cache_key(const char *hostname, const char *port,
                          const char *path, char *key, size_t key_capacity);
static int cache_get(const char *key, unsigned char *object, size_t *size);
static void cache_put(const char *key, const unsigned char *object,
                      size_t size);
static void send_error_response(int fd, int status, const char *short_message,
                                const char *detail);

int main(int argc, char **argv)
{
    int listenfd;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    /* A disconnected browser must not be able to terminate the proxy. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "Unable to ignore SIGPIPE\n");
        return 1;
    }

    listenfd = open_listenfd(argv[1]);
    if (listenfd < 0) {
        fprintf(stderr, "Unable to listen on port %s\n", argv[1]);
        return 1;
    }

    for (;;) {
        struct sockaddr_storage client_address;
        socklen_t client_length = sizeof(client_address);
        int clientfd = accept(listenfd, (SA *)&client_address, &client_length);
        int *connection;
        pthread_t tid;

        if (clientfd < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "accept failed: %s\n", strerror(errno));
            continue;
        }

        connection = malloc(sizeof(*connection));
        if (connection == NULL) {
            close(clientfd);
            continue;
        }
        *connection = clientfd;

        if (pthread_create(&tid, NULL, worker, connection) != 0) {
            close(clientfd);
            free(connection);
        }
    }
}

static void *worker(void *arg)
{
    int clientfd = *(int *)arg;

    free(arg);
    (void)pthread_detach(pthread_self());
    serve_client(clientfd);
    close(clientfd);
    return NULL;
}

static void serve_client(int clientfd)
{
    rio_t client_rio;
    char request_line[MAXLINE];
    char method[16];
    char uri[MAXLINE];
    char version[16];
    char host_header[MAXLINE] = "";
    char other_headers[MAX_HEADER_SIZE] = "";
    char hostname[MAX_HOST_SIZE];
    char port[MAX_PORT_SIZE];
    char path[MAXLINE];
    char generated_host[MAXLINE];
    char cache_key[MAX_CACHE_KEY];
    char outgoing[MAX_HEADER_SIZE + MAXLINE];
    unsigned char *object = NULL;
    size_t object_size = 0;
    ssize_t nread;
    int serverfd;

    rio_readinitb(&client_rio, clientfd);
    nread = rio_readlineb(&client_rio, request_line, sizeof(request_line));
    if (nread <= 0)
        return;

    if ((size_t)nread == sizeof(request_line) - 1 &&
        request_line[nread - 1] != '\n') {
        send_error_response(clientfd, 414, "URI Too Long",
                            "The request line is too long.");
        return;
    }
    if (memchr(request_line, '\0', (size_t)nread) != NULL) {
        send_error_response(clientfd, 400, "Bad Request",
                            "The request line contains invalid data.");
        return;
    }

    if (sscanf(request_line, "%15s %8191s %15s", method, uri, version) != 3) {
        send_error_response(clientfd, 400, "Bad Request",
                            "The request line is malformed.");
        return;
    }
    if (strcasecmp(method, "GET") != 0) {
        send_error_response(clientfd, 501, "Not Implemented",
                            "This proxy only supports GET requests.");
        return;
    }
    if (strncasecmp(version, "HTTP/", 5) != 0) {
        send_error_response(clientfd, 400, "Bad Request",
                            "The HTTP version is malformed.");
        return;
    }

    if (read_request_headers(&client_rio, host_header, sizeof(host_header),
                             other_headers, sizeof(other_headers)) < 0) {
        send_error_response(clientfd, 431, "Request Header Fields Too Large",
                            "The request headers are malformed or too large.");
        return;
    }

    if (strncasecmp(uri, "http://", 7) == 0) {
        if (parse_absolute_uri(uri, hostname, sizeof(hostname), port,
                               sizeof(port), path, sizeof(path),
                               generated_host, sizeof(generated_host)) < 0) {
            send_error_response(clientfd, 400, "Bad Request",
                                "The HTTP URL is malformed.");
            return;
        }
    } else if (uri[0] == '/') {
        if (host_header[0] == '\0' ||
            parse_authority(host_header, hostname, sizeof(hostname), port,
                            sizeof(port), generated_host,
                            sizeof(generated_host)) < 0 ||
            snprintf(path, sizeof(path), "%s", uri) >= (int)sizeof(path)) {
            send_error_response(clientfd, 400, "Bad Request",
                                "An origin-form request requires a valid Host header.");
            return;
        }
    } else {
        send_error_response(clientfd, 400, "Bad Request",
                            "Only plain HTTP URLs are supported.");
        return;
    }

    {
        char *fragment = strchr(path, '#');
        if (fragment != NULL)
            *fragment = '\0';
    }

    if (make_cache_key(hostname, port, path, cache_key,
                       sizeof(cache_key)) < 0) {
        send_error_response(clientfd, 414, "URI Too Long",
                            "The normalized URL is too long.");
        return;
    }

    object = malloc(MAX_OBJECT_SIZE);
    if (object != NULL && cache_get(cache_key, object, &object_size)) {
        (void)rio_writen(clientfd, object, object_size);
        free(object);
        return;
    }

    {
        const char *out_host = host_header[0] != '\0' ? host_header : generated_host;
        int written = snprintf(outgoing, sizeof(outgoing),
                               "GET %s HTTP/1.0\r\n"
                               "Host: %s\r\n"
                               "%s"
                               "Connection: close\r\n"
                               "Proxy-Connection: close\r\n"
                               "%s"
                               "\r\n",
                               path, out_host, user_agent_hdr, other_headers);

        if (written < 0 || (size_t)written >= sizeof(outgoing)) {
            free(object);
            send_error_response(clientfd, 431,
                                "Request Header Fields Too Large",
                                "The forwarded request would be too large.");
            return;
        }

        serverfd = open_clientfd(hostname, port);
        if (serverfd < 0) {
            free(object);
            send_error_response(clientfd, 502, "Bad Gateway",
                                "The origin server could not be reached.");
            return;
        }

        if (rio_writen(serverfd, outgoing, (size_t)written) != written) {
            close(serverfd);
            free(object);
            send_error_response(clientfd, 502, "Bad Gateway",
                                "The request could not be sent to the origin server.");
            return;
        }
    }

    {
        unsigned char buffer[MAXBUF];
        size_t total = 0;
        int cacheable = object != NULL;
        int complete = 0;
        int client_open = 1;

        for (;;) {
            nread = read(serverfd, buffer, sizeof(buffer));
            if (nread > 0) {
                if (client_open &&
                    rio_writen(clientfd, buffer, (size_t)nread) != nread)
                    client_open = 0;
                if (cacheable) {
                    if (total + (size_t)nread <= MAX_OBJECT_SIZE) {
                        memcpy(object + total, buffer, (size_t)nread);
                        total += (size_t)nread;
                    } else {
                        cacheable = 0;
                    }
                }
            } else if (nread == 0) {
                complete = 1;
                break;
            } else if (errno != EINTR) {
                break;
            }
        }

        if (complete && cacheable)
            cache_put(cache_key, object, total);
    }

    close(serverfd);
    free(object);
}

static int read_request_headers(rio_t *rio, char *host_header,
                                size_t host_capacity, char *other_headers,
                                size_t other_capacity)
{
    char line[MAXLINE];
    size_t other_length = 0;
    ssize_t nread;

    while ((nread = rio_readlineb(rio, line, sizeof(line))) > 0) {
        char *colon;
        char *value;
        char *end;
        size_t name_length;
        size_t line_length;

        if ((size_t)nread == sizeof(line) - 1 && line[nread - 1] != '\n')
            return -1;
        if (memchr(line, '\0', (size_t)nread) != NULL)
            return -1;

        line_length = (size_t)nread;
        while (line_length > 0 &&
               (line[line_length - 1] == '\r' || line[line_length - 1] == '\n'))
            line[--line_length] = '\0';
        if (line_length == 0)
            return 0;

        colon = memchr(line, ':', line_length);
        if (colon == NULL)
            return -1;
        end = colon;
        while (end > line && isspace((unsigned char)end[-1]))
            --end;
        name_length = (size_t)(end - line);
        if (name_length == 0)
            return -1;

        value = colon + 1;
        while (*value == ' ' || *value == '\t')
            ++value;
        end = line + line_length;
        while (end > value && isspace((unsigned char)end[-1]))
            --end;
        *end = '\0';

        if (name_length == 4 && strncasecmp(line, "Host", 4) == 0) {
            char *host_character;
            for (host_character = value; *host_character != '\0';
                 ++host_character) {
                if (iscntrl((unsigned char)*host_character) ||
                    isspace((unsigned char)*host_character))
                    return -1;
            }
            if (*value == '\0' ||
                snprintf(host_header, host_capacity, "%s", value) >=
                    (int)host_capacity)
                return -1;
        } else if ((name_length == 10 &&
                    strncasecmp(line, "User-Agent", 10) == 0) ||
                   (name_length == 10 &&
                    strncasecmp(line, "Connection", 10) == 0) ||
                   (name_length == 16 &&
                    strncasecmp(line, "Proxy-Connection", 16) == 0)) {
            continue;
        } else {
            size_t normalized_length;
            line_length = (size_t)(end - line);
            normalized_length = line_length + 2;
            if (other_length + normalized_length >= other_capacity)
                return -1;
            memcpy(other_headers + other_length, line, line_length);
            other_length += line_length;
            memcpy(other_headers + other_length, "\r\n", 2);
            other_length += 2;
            other_headers[other_length] = '\0';
        }
    }

    return -1;
}

static int parse_absolute_uri(const char *uri, char *hostname,
                              size_t hostname_capacity, char *port,
                              size_t port_capacity, char *path,
                              size_t path_capacity, char *generated_host,
                              size_t generated_host_capacity)
{
    const char *authority_start = uri + 7;
    const char *target_start = strpbrk(authority_start, "/?#");
    size_t authority_length = target_start == NULL
                                  ? strlen(authority_start)
                                  : (size_t)(target_start - authority_start);
    char authority[MAXLINE];

    if (authority_length == 0 || authority_length >= sizeof(authority))
        return -1;
    memcpy(authority, authority_start, authority_length);
    authority[authority_length] = '\0';

    if (parse_authority(authority, hostname, hostname_capacity, port,
                        port_capacity, generated_host,
                        generated_host_capacity) < 0)
        return -1;

    if (target_start == NULL || *target_start == '#') {
        if (snprintf(path, path_capacity, "/") >= (int)path_capacity)
            return -1;
    } else if (*target_start == '?') {
        if (snprintf(path, path_capacity, "/%s", target_start) >=
            (int)path_capacity)
            return -1;
    } else if (snprintf(path, path_capacity, "%s", target_start) >=
               (int)path_capacity) {
        return -1;
    }
    return 0;
}

static int parse_authority(const char *authority, char *hostname,
                           size_t hostname_capacity, char *port,
                           size_t port_capacity, char *formatted_host,
                           size_t formatted_host_capacity)
{
    char copy[MAXLINE];
    char *start;
    char *end;
    char *port_text = NULL;
    int ipv6 = 0;
    unsigned long port_number = 80;

    if (snprintf(copy, sizeof(copy), "%s", authority) >= (int)sizeof(copy))
        return -1;
    start = copy;
    while (*start == ' ' || *start == '\t')
        ++start;
    end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1]))
        *--end = '\0';
    if (*start == '\0' || strchr(start, '@') != NULL)
        return -1;

    if (*start == '[') {
        char *closing = strchr(start + 1, ']');
        if (closing == NULL || closing == start + 1)
            return -1;
        ipv6 = 1;
        *closing = '\0';
        if (closing[1] == ':')
            port_text = closing + 2;
        else if (closing[1] != '\0')
            return -1;
        ++start;
    } else {
        char *first_colon = strchr(start, ':');
        char *last_colon = strrchr(start, ':');
        if (first_colon != NULL) {
            if (first_colon != last_colon)
                return -1;
            *last_colon = '\0';
            port_text = last_colon + 1;
        }
    }

    if (*start == '\0' || strlen(start) >= hostname_capacity)
        return -1;
    for (end = start; *end != '\0'; ++end) {
        if (iscntrl((unsigned char)*end) || isspace((unsigned char)*end) ||
            *end == '/' || *end == '?' || *end == '#')
            return -1;
    }

    if (port_text != NULL) {
        char *number_end;
        unsigned long parsed;
        if (*port_text == '\0')
            return -1;
        errno = 0;
        parsed = strtoul(port_text, &number_end, 10);
        if (errno != 0 || *number_end != '\0' || parsed == 0 ||
            parsed > 65535)
            return -1;
        port_number = parsed;
    }

    if (snprintf(hostname, hostname_capacity, "%s", start) >=
            (int)hostname_capacity ||
        snprintf(port, port_capacity, "%lu", port_number) >=
            (int)port_capacity)
        return -1;

    if (ipv6) {
        if (port_number == 80) {
            if (snprintf(formatted_host, formatted_host_capacity, "[%s]",
                         hostname) >= (int)formatted_host_capacity)
                return -1;
        } else if (snprintf(formatted_host, formatted_host_capacity,
                            "[%s]:%s", hostname, port) >=
                   (int)formatted_host_capacity) {
            return -1;
        }
    } else if (port_number == 80) {
        if (snprintf(formatted_host, formatted_host_capacity, "%s", hostname) >=
            (int)formatted_host_capacity)
            return -1;
    } else if (snprintf(formatted_host, formatted_host_capacity, "%s:%s",
                        hostname, port) >= (int)formatted_host_capacity) {
        return -1;
    }
    return 0;
}

static int make_cache_key(const char *hostname, const char *port,
                          const char *path, char *key, size_t key_capacity)
{
    char lowered[MAX_HOST_SIZE];
    size_t i;
    int written;

    if (strlen(hostname) >= sizeof(lowered))
        return -1;
    for (i = 0; hostname[i] != '\0'; ++i)
        lowered[i] = (char)tolower((unsigned char)hostname[i]);
    lowered[i] = '\0';

    written = snprintf(key, key_capacity, "http://%s:%s%s", lowered, port,
                       path);
    return written < 0 || (size_t)written >= key_capacity ? -1 : 0;
}

static int cache_get(const char *key, unsigned char *object, size_t *size)
{
    cache_entry_t *entry;
    int found = 0;

    pthread_rwlock_rdlock(&cache_lock);
    for (entry = cache_head; entry != NULL; entry = entry->next) {
        if (strcmp(entry->key, key) == 0) {
            memcpy(object, entry->data, entry->size);
            *size = entry->size;
            found = 1;
            break;
        }
    }
    pthread_rwlock_unlock(&cache_lock);

    /* Keep cache reads concurrent; update the approximate-LRU clock after. */
    if (found) {
        pthread_rwlock_wrlock(&cache_lock);
        for (entry = cache_head; entry != NULL; entry = entry->next) {
            if (strcmp(entry->key, key) == 0) {
                entry->last_used = ++cache_clock;
                break;
            }
        }
        pthread_rwlock_unlock(&cache_lock);
    }
    return found;
}

static void cache_put(const char *key, const unsigned char *object, size_t size)
{
    cache_entry_t *new_entry;
    cache_entry_t *entry;
    cache_entry_t *previous;

    if (size > MAX_OBJECT_SIZE || size > MAX_CACHE_SIZE)
        return;

    new_entry = malloc(sizeof(*new_entry));
    if (new_entry == NULL)
        return;
    new_entry->key = malloc(strlen(key) + 1);
    new_entry->data = malloc(size == 0 ? 1 : size);
    if (new_entry->key == NULL || new_entry->data == NULL) {
        free(new_entry->key);
        free(new_entry->data);
        free(new_entry);
        return;
    }
    strcpy(new_entry->key, key);
    if (size > 0)
        memcpy(new_entry->data, object, size);
    new_entry->size = size;
    new_entry->next = NULL;

    pthread_rwlock_wrlock(&cache_lock);

    previous = NULL;
    for (entry = cache_head; entry != NULL; entry = entry->next) {
        if (strcmp(entry->key, key) == 0) {
            if (previous == NULL)
                cache_head = entry->next;
            else
                previous->next = entry->next;
            cache_size -= entry->size;
            free(entry->key);
            free(entry->data);
            free(entry);
            break;
        }
        previous = entry;
    }

    while (cache_head != NULL && cache_size + size > MAX_CACHE_SIZE) {
        cache_entry_t *victim = cache_head;
        cache_entry_t *victim_previous = NULL;

        previous = cache_head;
        for (entry = cache_head->next; entry != NULL; entry = entry->next) {
            if (entry->last_used < victim->last_used) {
                victim = entry;
                victim_previous = previous;
            }
            previous = entry;
        }

        if (victim_previous == NULL)
            cache_head = victim->next;
        else
            victim_previous->next = victim->next;
        cache_size -= victim->size;
        free(victim->key);
        free(victim->data);
        free(victim);
    }

    new_entry->last_used = ++cache_clock;
    new_entry->next = cache_head;
    cache_head = new_entry;
    cache_size += size;
    pthread_rwlock_unlock(&cache_lock);
}

static void send_error_response(int fd, int status, const char *short_message,
                                const char *detail)
{
    char body[MAXBUF];
    char headers[MAXBUF];
    int body_length;
    int header_length;

    body_length = snprintf(body, sizeof(body),
                           "<!doctype html>\n"
                           "<html><head><title>%d %s</title></head>\n"
                           "<body><h1>%d %s</h1><p>%s</p></body></html>\n",
                           status, short_message, status, short_message, detail);
    if (body_length < 0)
        return;
    if ((size_t)body_length >= sizeof(body))
        body_length = (int)sizeof(body) - 1;

    header_length = snprintf(headers, sizeof(headers),
                             "HTTP/1.0 %d %s\r\n"
                             "Content-Type: text/html; charset=utf-8\r\n"
                             "Content-Length: %d\r\n"
                             "Connection: close\r\n"
                             "\r\n",
                             status, short_message, body_length);
    if (header_length < 0 || (size_t)header_length >= sizeof(headers))
        return;

    (void)rio_writen(fd, headers, (size_t)header_length);
    (void)rio_writen(fd, body, (size_t)body_length);
}
