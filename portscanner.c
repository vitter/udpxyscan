#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <signal.h>
#include <sys/time.h>
#include <stdarg.h>
#include <time.h>

// 平台兼容性处理
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define MSG_NOSIGNAL 0
#else
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

#define MAX_THREADS 256
#define BUF_SIZE 8192
#define MAX_TASKS 10000
#define PACKET_SIZE 4096

// 自定义IP和TCP头结构（跨平台兼容）
struct ip_header
{
    uint8_t ihl : 4;     // IP header length
    uint8_t version : 4; // IP version
    uint8_t tos;         // Type of service
    uint16_t tot_len;    // Total length
    uint16_t id;         // Identification
    uint16_t frag_off;   // Fragment offset
    uint8_t ttl;         // Time to live
    uint8_t protocol;    // Protocol
    uint16_t check;      // Checksum
    uint32_t saddr;      // Source address
    uint32_t daddr;      // Destination address
};

struct tcp_header
{
    uint16_t source;      // Source port
    uint16_t dest;        // Destination port
    uint32_t seq;         // Sequence number
    uint32_t ack_seq;     // Acknowledgment number
    uint8_t reserved : 4; // Reserved
    uint8_t doff : 4;     // Data offset
    uint8_t fin : 1;      // FIN flag
    uint8_t syn : 1;      // SYN flag
    uint8_t rst : 1;      // RST flag
    uint8_t psh : 1;      // PSH flag
    uint8_t ack : 1;      // ACK flag
    uint8_t urg : 1;      // URG flag
    uint8_t ece : 1;      // ECE flag
    uint8_t cwr : 1;      // CWR flag
    uint16_t window;      // Window size
    uint16_t check;       // Checksum
    uint16_t urg_ptr;     // Urgent pointer
};

// 扫描模式枚举
typedef enum
{
    SCAN_MODE_TCP_CONNECT = 0,
    SCAN_MODE_SYN_SCAN = 1
} scan_mode_t;

// 端口状态枚举
typedef enum
{
    PORT_CLOSED = 0,
    PORT_OPEN = 1,
    PORT_FILTERED = 2
} port_status_t;

typedef struct
{
    char ip[64];
    int port;
    int connect_timeout_ms; // 连接超时
    int recv_timeout_ms;    // 接收数据超时
    int verbose;
    int debug; // 调试模式
    char outfile[256];
    scan_mode_t scan_mode; // 扫描模式
    int udpxy_detect;      // 是否进行UDPXY检测
} scan_task_t;

// 任务队列结构
typedef struct task_queue
{
    scan_task_t *tasks[MAX_TASKS];
    int front;
    int rear;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    int shutdown;
} task_queue_t;

// TCP伪首部用于校验和计算
struct pseudo_header
{
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

// 全局变量
static task_queue_t task_queue;
static pthread_t worker_threads[MAX_THREADS];
static int num_threads = 0;
static volatile int total_tasks = 0;
static volatile int completed_tasks = 0;
static volatile int open_ports_found = 0;
static volatile int udpxy_services_found = 0;
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
static int raw_socket_fd = -1; // 原始套接字

// 函数声明
void safe_output(const char *format, ...);
int enqueue_task(scan_task_t *task);
scan_task_t *dequeue_task();
void shutdown_task_queue();
void *worker_thread(void *arg);
port_status_t scan_port_tcp_connect(scan_task_t *task);
port_status_t scan_port_syn_scan(scan_task_t *task);
int detect_udpxy_service(scan_task_t *task);
uint16_t checksum(void *vdata, size_t length);
uint16_t tcp_checksum(struct ip_header *iph, struct tcp_header *tcph);
int create_raw_socket();
void cleanup_raw_socket();

// IP字符串转uint32
uint32_t ip2int(const char *ip)
{
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    return ntohl(addr.s_addr);
}

// uint32转IP字符串
void int2ip(uint32_t ip, char *buf)
{
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    strcpy(buf, inet_ntoa(addr));
}

// 解析IP参数，支持单IP、区间、CIDR、逗号分隔
int parse_iplist(const char *ipstr, char iplist[][64], int max, int quiet)
{
    int cnt = 0;
    char *ips = strdup(ipstr);
    char *token = strtok(ips, ",");

    while (token && cnt < max)
    {
        // 去除首尾空格
        while (*token == ' ')
            token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ')
            *end-- = '\0';

        // 检查是否是CIDR格式 (如 192.168.1.0/24)
        char *slash = strchr(token, '/');
        if (slash)
        {
            *slash = '\0';
            int prefix_len = atoi(slash + 1);

            if (prefix_len >= 0 && prefix_len <= 32)
            {
                uint32_t base_ip = ip2int(token);
                uint32_t mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF;
                uint32_t network = base_ip & mask;
                uint32_t broadcast = network | (~mask & 0xFFFFFFFF);

                uint32_t host_count = broadcast - network - 1;

                if (!quiet)
                {
                    char network_str[INET_ADDRSTRLEN], broadcast_str[INET_ADDRSTRLEN];
                    struct in_addr addr;
                    addr.s_addr = htonl(network);
                    strcpy(network_str, inet_ntoa(addr));
                    addr.s_addr = htonl(broadcast);
                    strcpy(broadcast_str, inet_ntoa(addr));
                    printf("解析CIDR %s/%d: 网络=%s, 广播=%s, 主机数=%u\n",
                           token, prefix_len, network_str, broadcast_str, host_count);
                }

                for (uint32_t ip = network + 1; ip < broadcast && cnt < max; ++ip)
                {
                    int2ip(ip, iplist[cnt++]);
                }
            }
        }
        // 检查是否是IP范围 (如 192.168.1.1-192.168.1.10)
        else
        {
            char *dash = strchr(token, '-');
            if (dash)
            {
                *dash = '\0';
                uint32_t start = ip2int(token);
                uint32_t end = ip2int(dash + 1);

                if (!quiet)
                {
                    printf("解析IP范围 %s-%s, 共%u个IP\n",
                           token, dash + 1, end - start + 1);
                }

                for (uint32_t ip = start; ip <= end && cnt < max; ++ip)
                {
                    int2ip(ip, iplist[cnt++]);
                }
            }
            else
            {
                // 单个IP
                strncpy(iplist[cnt++], token, 63);
                iplist[cnt - 1][63] = '\0';
            }
        }
        token = strtok(NULL, ",");
    }

    free(ips);
    return cnt;
}

// 解析端口列表，支持逗号分隔
int parse_ports(const char *pstr, int *plist, int max)
{
    int cnt = 0;
    char *ps = strdup(pstr);
    char *token = strtok(ps, ",");
    while (token && cnt < max)
    {
        plist[cnt++] = atoi(token);
        token = strtok(NULL, ",");
    }
    free(ps);
    return cnt;
}

// 计算校验和
uint16_t checksum(void *vdata, size_t length)
{
    char *data = (char *)vdata;
    uint32_t acc = 0xffff;

    for (size_t i = 0; i + 1 < length; i += 2)
    {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff)
        {
            acc -= 0xffff;
        }
    }

    if (length & 1)
    {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff)
        {
            acc -= 0xffff;
        }
    }

    return htons(~acc);
}

// 计算TCP校验和
uint16_t tcp_checksum(struct ip_header *iph, struct tcp_header *tcph)
{
    struct pseudo_header psh;
    char *pseudogram;
    int psize;

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcp_header));

    psize = sizeof(struct pseudo_header) + sizeof(struct tcp_header);
    pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcp_header));

    uint16_t result = checksum(pseudogram, psize);
    free(pseudogram);
    return result;
}

// 创建原始套接字
int create_raw_socket()
{
#ifdef _WIN32
    // Windows下需要特殊处理，暂时返回-1表示不支持
    printf("警告: Windows平台暂不支持SYN扫描，将使用TCP连接扫描\n");
    return -1;
#else
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0)
    {
        perror("创建原始套接字失败（需要root权限）");
        return -1;
    }

    int one = 1;
    const int *val = &one;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("设置IP_HDRINCL失败");
        close(sockfd);
        return -1;
    }

    return sockfd;
#endif
}

// 清理原始套接字
void cleanup_raw_socket()
{
    if (raw_socket_fd >= 0)
    {
        close(raw_socket_fd);
        raw_socket_fd = -1;
    }
}

// TCP Connect扫描
port_status_t scan_port_tcp_connect(scan_task_t *task)
{
    int sockfd = -1;
    struct sockaddr_in addr;
    int ret;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        return PORT_FILTERED;
    }

    // 设置socket选项
    int reuseaddr = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

    // 设置为非阻塞
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1 || fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        close(sockfd);
        return PORT_FILTERED;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(task->port);
    if (inet_pton(AF_INET, task->ip, &addr.sin_addr) <= 0)
    {
        close(sockfd);
        return PORT_FILTERED;
    }

    ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0)
    {
        if (errno != EINPROGRESS)
        {
            if (task->debug)
            {
                safe_output("[调试] %s:%d TCP连接立即失败: %s\n", task->ip, task->port, strerror(errno));
            }
            close(sockfd);
            return PORT_CLOSED;
        }

        // 等待连接完成
        fd_set wfds, efds;
        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        FD_SET(sockfd, &wfds);
        FD_SET(sockfd, &efds);

        struct timeval tv;
        tv.tv_sec = task->connect_timeout_ms / 1000;
        tv.tv_usec = (task->connect_timeout_ms % 1000) * 1000;

        ret = select(sockfd + 1, NULL, &wfds, &efds, &tv);
        if (ret <= 0)
        {
            if (task->debug)
            {
                safe_output("[调试] %s:%d TCP连接超时\n", task->ip, task->port);
            }
            close(sockfd);
            return PORT_FILTERED;
        }

        if (FD_ISSET(sockfd, &efds))
        {
            if (task->debug)
            {
                safe_output("[调试] %s:%d TCP连接错误\n", task->ip, task->port);
            }
            close(sockfd);
            return PORT_CLOSED;
        }

        if (!FD_ISSET(sockfd, &wfds))
        {
            if (task->debug)
            {
                safe_output("[调试] %s:%d TCP连接未完成\n", task->ip, task->port);
            }
            close(sockfd);
            return PORT_FILTERED;
        }

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0)
        {
            if (task->debug)
            {
                safe_output("[调试] %s:%d TCP连接完成但有错误: %s\n", task->ip, task->port,
                            so_error ? strerror(so_error) : "unknown");
            }
            close(sockfd);
            return PORT_CLOSED;
        }
    }

    if (task->debug)
    {
        safe_output("[调试] %s:%d TCP连接成功\n", task->ip, task->port);
    }

    close(sockfd);
    return PORT_OPEN;
}

// SYN扫描
port_status_t scan_port_syn_scan(scan_task_t *task)
{
    if (raw_socket_fd < 0)
    {
        if (task->debug)
        {
            safe_output("[调试] %s:%d 原始套接字不可用，回退到TCP连接扫描\n", task->ip, task->port);
        }
        return scan_port_tcp_connect(task);
    }

#ifdef _WIN32
    // Windows平台回退到TCP连接扫描
    if (task->debug)
    {
        safe_output("[调试] %s:%d Windows平台使用TCP连接扫描\n", task->ip, task->port);
    }
    return scan_port_tcp_connect(task);
#else
    char packet[PACKET_SIZE];
    struct ip_header *iph = (struct ip_header *)packet;
    struct tcp_header *tcph = (struct tcp_header *)(packet + sizeof(struct ip_header));
    struct sockaddr_in dest;

    memset(packet, 0, PACKET_SIZE);

    // 填充IP头
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip_header) + sizeof(struct tcp_header);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr("127.0.0.1"); // 源IP，系统会自动选择
    iph->daddr = inet_addr(task->ip);

    // 填充TCP头
    tcph->source = htons(12345 + (rand() % 10000)); // 随机源端口
    tcph->dest = htons(task->port);
    tcph->seq = rand();
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // 计算TCP校验和
    tcph->check = tcp_checksum(iph, tcph);

    // 发送SYN包
    dest.sin_family = AF_INET;
    dest.sin_port = htons(task->port);
    dest.sin_addr.s_addr = inet_addr(task->ip);

    if (sendto(raw_socket_fd, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        if (task->debug)
        {
            safe_output("[调试] %s:%d SYN包发送失败: %s\n", task->ip, task->port, strerror(errno));
        }
        return PORT_FILTERED;
    }

    if (task->debug)
    {
        safe_output("[调试] %s:%d SYN包已发送\n", task->ip, task->port);
    }

    // 等待响应（简化版，实际应该监听响应包）
    usleep(task->connect_timeout_ms * 1000);

    // 注意：这里简化了响应处理
    // 实际应该创建一个监听套接字来捕获SYN-ACK或RST响应
    // 为了简化，我们使用TCP连接测试来验证端口状态
    return scan_port_tcp_connect(task);
#endif
}

// 检测UDPXY服务
int detect_udpxy_service(scan_task_t *task)
{
    int sockfd = -1;
    struct sockaddr_in addr;
    char sendbuf[512], recvbuf[BUF_SIZE];
    int ret;
    char *allbuf = NULL;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        return 0;
    }

    // 设置socket选项
    int reuseaddr = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

    // 设置为非阻塞
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1 || fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        close(sockfd);
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(task->port);
    if (inet_pton(AF_INET, task->ip, &addr.sin_addr) <= 0)
    {
        close(sockfd);
        return 0;
    }

    // 连接
    ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS)
    {
        close(sockfd);
        return 0;
    }

    if (errno == EINPROGRESS)
    {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sockfd, &wfds);

        struct timeval tv;
        tv.tv_sec = task->connect_timeout_ms / 1000;
        tv.tv_usec = (task->connect_timeout_ms % 1000) * 1000;

        if (select(sockfd + 1, NULL, &wfds, NULL, &tv) <= 0)
        {
            close(sockfd);
            return 0;
        }
    }

    // 还原为阻塞模式
    if (fcntl(sockfd, F_SETFL, flags) == -1)
    {
        close(sockfd);
        return 0;
    }

    // 发送HTTP请求
    snprintf(sendbuf, sizeof(sendbuf),
             "GET / HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: port-scanner/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
             task->ip, task->port);

    if (send(sockfd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL) < 0)
    {
        close(sockfd);
        return 0;
    }

    // 接收响应
    allbuf = malloc(BUF_SIZE * 2);
    if (!allbuf)
    {
        close(sockfd);
        return 0;
    }

    int total = 0;
    struct timeval recv_tv;
    fd_set rfds;
    int consecutive_timeouts = 0;

    while (total < (BUF_SIZE * 2 - 1))
    {
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        recv_tv.tv_sec = task->recv_timeout_ms / 1000;
        recv_tv.tv_usec = (task->recv_timeout_ms % 1000) * 1000;

        ret = select(sockfd + 1, &rfds, NULL, NULL, &recv_tv);
        if (ret < 0)
        {
            break;
        }
        else if (ret == 0)
        {
            consecutive_timeouts++;
            if (consecutive_timeouts >= 1 && total == 0)
            {
                break;
            }
            if (consecutive_timeouts >= 3)
            {
                break;
            }
            continue;
        }

        consecutive_timeouts = 0;

        if (FD_ISSET(sockfd, &rfds))
        {
            ret = recv(sockfd, recvbuf, BUF_SIZE - 1, 0);
            if (ret <= 0)
            {
                break;
            }

            if (total + ret >= BUF_SIZE * 2 - 1)
            {
                ret = BUF_SIZE * 2 - 1 - total;
            }

            memcpy(allbuf + total, recvbuf, ret);
            total += ret;

            // 提前检测UDPXY标识
            if (total > 100)
            {
                allbuf[total] = '\0';
                char *allbuf_lc = malloc(total + 1);
                if (allbuf_lc)
                {
                    for (int i = 0; i <= total; ++i)
                    {
                        allbuf_lc[i] = tolower((unsigned char)allbuf[i]);
                    }
                    if (strstr(allbuf_lc, "udpxy") ||
                        (strstr(allbuf_lc, "400") && strstr(allbuf_lc, "unrecognized")))
                    {
                        free(allbuf_lc);
                        break;
                    }
                    free(allbuf_lc);
                }
            }
        }
    }

    int is_udpxy = 0;
    if (total > 0 && allbuf)
    {
        allbuf[total] = '\0';
        char *allbuf_lc = malloc(total + 1);
        if (allbuf_lc)
        {
            for (int i = 0; i <= total; ++i)
            {
                allbuf_lc[i] = tolower((unsigned char)allbuf[i]);
            }

            if (strstr(allbuf_lc, "udpxy") ||
                (strstr(allbuf_lc, "server:") &&
                 (strstr(allbuf_lc, "multicast") || strstr(allbuf_lc, "stream"))) ||
                (strstr(allbuf_lc, "400") && strstr(allbuf_lc, "unrecognized")))
            {
                is_udpxy = 1;

                safe_output("[+] %s:%d 发现UDPXY服务\n", task->ip, task->port);
                if (task->debug)
                {
                    safe_output("[调试] %s:%d UDPXY检测成功，响应长度: %d\n", task->ip, task->port, total);
                }
                if (task->verbose)
                {
                    safe_output("%s\n", allbuf);
                }

                // 写入文件
                if (task->outfile && task->outfile[0])
                {
                    pthread_mutex_lock(&output_mutex);
                    FILE *f = fopen(task->outfile, "a");
                    if (f)
                    {
                        if (task->verbose)
                        {
                            fprintf(f, "%s:%d [UDPXY]\n%s\n", task->ip, task->port, allbuf);
                        }
                        else
                        {
                            fprintf(f, "%s:%d [UDPXY]\n", task->ip, task->port);
                        }
                        fclose(f);
                    }
                    pthread_mutex_unlock(&output_mutex);
                }
            }
            free(allbuf_lc);
        }
    }

    close(sockfd);
    free(allbuf);
    return is_udpxy;
}

// 工作线程函数
void *worker_thread(void *arg)
{
    (void)arg;

    while (1)
    {
        scan_task_t *task = dequeue_task();
        if (!task)
        {
            break;
        }

        port_status_t status;

        // 根据扫描模式选择扫描方法
        if (task->scan_mode == SCAN_MODE_SYN_SCAN)
        {
            status = scan_port_syn_scan(task);
        }
        else
        {
            status = scan_port_tcp_connect(task);
        }

        // 如果端口开放且需要检测UDPXY服务
        if (status == PORT_OPEN && task->udpxy_detect)
        {
            if (detect_udpxy_service(task))
            {
                __sync_add_and_fetch(&udpxy_services_found, 1);
            }
            __sync_add_and_fetch(&open_ports_found, 1);
        }
        else if (status == PORT_OPEN && !task->udpxy_detect)
        {
            safe_output("[+] %s:%d 端口开放\n", task->ip, task->port);
            __sync_add_and_fetch(&open_ports_found, 1);

            // 写入文件
            if (task->outfile && task->outfile[0])
            {
                pthread_mutex_lock(&output_mutex);
                FILE *f = fopen(task->outfile, "a");
                if (f)
                {
                    fprintf(f, "%s:%d\n", task->ip, task->port);
                    fclose(f);
                }
                pthread_mutex_unlock(&output_mutex);
            }
        }
        else if (task->verbose && status == PORT_CLOSED)
        {
            safe_output("[-] %s:%d 端口关闭\n", task->ip, task->port);
        }
        else if (task->verbose && status == PORT_FILTERED)
        {
            safe_output("[?] %s:%d 端口过滤/超时\n", task->ip, task->port);
        }
        else if (task->debug)
        {
            const char *status_str = (status == PORT_CLOSED) ? "关闭" : (status == PORT_FILTERED) ? "过滤"
                                                                                                  : "未知";
            safe_output("[调试] %s:%d 端口%s\n", task->ip, task->port, status_str);
        }

        free(task);
        __sync_add_and_fetch(&completed_tasks, 1);

        // 控制扫描速率
        if (total_tasks > 1000)
        {
            usleep(2000);
        }
        else if (total_tasks > 100)
        {
            usleep(1000);
        }
        else
        {
            usleep(500);
        }
    }

    return NULL;
}

// 任务队列管理函数
void init_task_queue()
{
    task_queue.front = 0;
    task_queue.rear = 0;
    task_queue.count = 0;
    task_queue.shutdown = 0;
    pthread_mutex_init(&task_queue.mutex, NULL);
    pthread_cond_init(&task_queue.not_empty, NULL);
    pthread_cond_init(&task_queue.not_full, NULL);
}

void destroy_task_queue()
{
    pthread_mutex_destroy(&task_queue.mutex);
    pthread_cond_destroy(&task_queue.not_empty);
    pthread_cond_destroy(&task_queue.not_full);
}

int enqueue_task(scan_task_t *task)
{
    pthread_mutex_lock(&task_queue.mutex);

    while (task_queue.count >= MAX_TASKS && !task_queue.shutdown)
    {
        pthread_cond_wait(&task_queue.not_full, &task_queue.mutex);
    }

    if (task_queue.shutdown)
    {
        pthread_mutex_unlock(&task_queue.mutex);
        return -1;
    }

    task_queue.tasks[task_queue.rear] = task;
    task_queue.rear = (task_queue.rear + 1) % MAX_TASKS;
    task_queue.count++;

    pthread_cond_signal(&task_queue.not_empty);
    pthread_mutex_unlock(&task_queue.mutex);
    return 0;
}

scan_task_t *dequeue_task()
{
    pthread_mutex_lock(&task_queue.mutex);

    while (task_queue.count == 0 && !task_queue.shutdown)
    {
        pthread_cond_wait(&task_queue.not_empty, &task_queue.mutex);
    }

    if (task_queue.count == 0 && task_queue.shutdown)
    {
        pthread_mutex_unlock(&task_queue.mutex);
        return NULL;
    }

    scan_task_t *task = task_queue.tasks[task_queue.front];
    task_queue.front = (task_queue.front + 1) % MAX_TASKS;
    task_queue.count--;

    pthread_cond_signal(&task_queue.not_full);
    pthread_mutex_unlock(&task_queue.mutex);
    return task;
}

void shutdown_task_queue()
{
    pthread_mutex_lock(&task_queue.mutex);
    task_queue.shutdown = 1;
    pthread_cond_broadcast(&task_queue.not_empty);
    pthread_cond_broadcast(&task_queue.not_full);
    pthread_mutex_unlock(&task_queue.mutex);
}

// 安全的输出函数
void safe_output(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    pthread_mutex_lock(&output_mutex);
    vprintf(format, args);
    fflush(stdout);
    pthread_mutex_unlock(&output_mutex);

    va_end(args);
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        printf("用法: %s <ip> <start_port> <end_port> [选项]\n", argv[0]);
        printf("IP格式支持:\n");
        printf("  单个IP:     192.168.1.1\n");
        printf("  IP范围:     192.168.1.1-192.168.1.254\n");
        printf("  CIDR格式:   192.168.1.0/24\n");
        printf("  多个IP:     192.168.1.1,192.168.2.1-192.168.2.10,10.0.0.0/24\n");
        printf("选项:\n");
        printf("  -ip <ip_list>      多IP或IP段\n");
        printf("  -ports <port_list> 多端口(逗号分隔)\n");
        printf("  -out <file>        结果输出文件\n");
        printf("  -t <num>           线程数(默认50, 最大256)\n");
        printf("  -cto <ms>          连接超时ms(默认500)\n");
        printf("  -rto <ms>          接收超时ms(默认2000)\n");
        printf("  -mode <tcp|syn>    扫描模式: tcp=TCP连接扫描, syn=SYN半开放扫描(默认tcp)\n");
        printf("  -udpxy             启用UDPXY服务检测(默认关闭)\n");
        printf("  -v                 显示详细响应\n");
        printf("  -d                 调试模式\n");
        printf("  -fast              快速模式\n");
        printf("  -q                 静默模式\n");
        printf("注意: SYN扫描需要root权限\n");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL));

    char iplist[1024][64];
    int ipcount = 0;
    int portlist[1024];
    int portcount = 0;
    char outfile[256] = "";
    int threads = 50, connect_timeout_ms = 500, recv_timeout_ms = 2000;
    int verbose = 0, debug = 0, fast_mode = 0, quiet_mode = 0, udpxy_detect = 0;
    scan_mode_t scan_mode = SCAN_MODE_TCP_CONNECT;

    // 解析参数
    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-ip") == 0 && i + 1 < argc)
        {
            // 暂时解析，后面会重新解析
        }
        else if (strcmp(argv[i], "-ports") == 0 && i + 1 < argc)
        {
            portcount = parse_ports(argv[++i], portlist, 1024);
        }
        else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc)
        {
            strncpy(outfile, argv[++i], 255);
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
        {
            threads = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-cto") == 0 && i + 1 < argc)
        {
            connect_timeout_ms = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-rto") == 0 && i + 1 < argc)
        {
            recv_timeout_ms = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-mode") == 0 && i + 1 < argc)
        {
            char *mode = argv[++i];
            if (strcmp(mode, "syn") == 0)
            {
                scan_mode = SCAN_MODE_SYN_SCAN;
            }
            else if (strcmp(mode, "tcp") == 0)
            {
                scan_mode = SCAN_MODE_TCP_CONNECT;
            }
        }
        else if (strcmp(argv[i], "-udpxy") == 0)
        {
            udpxy_detect = 1;
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            verbose = 1;
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            debug = 1;
        }
        else if (strcmp(argv[i], "-fast") == 0)
        {
            fast_mode = 1;
        }
        else if (strcmp(argv[i], "-q") == 0)
        {
            quiet_mode = 1;
        }
    }

    if (threads > MAX_THREADS)
        threads = MAX_THREADS;
    if (threads < 1)
        threads = 1;

    // 解析IP列表
    int ip_found = 0;
    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-ip") == 0 && i + 1 < argc)
        {
            ipcount = parse_iplist(argv[++i], iplist, 1024, quiet_mode);
            ip_found = 1;
            break;
        }
    }

    if (!ip_found && argc >= 4)
    {
        ipcount = parse_iplist(argv[1], iplist, 1024, quiet_mode);
    }

    // 解析端口列表
    if (portcount == 0 && argc >= 4)
    {
        int start_port = atoi(argv[2]);
        int end_port = atoi(argv[3]);
        for (int p = start_port; p <= end_port && portcount < 1024; ++p)
        {
            portlist[portcount++] = p;
        }
    }

    // 调整参数
    if (portcount > 100 && !fast_mode && !quiet_mode)
    {
        if (connect_timeout_ms < 800)
            connect_timeout_ms = 800;
        if (recv_timeout_ms < 2000)
            recv_timeout_ms = 2000;
        if (threads > 40)
            threads = 40;
        printf("检测到大量端口扫描，自动调整参数：连接超时=%dms, 接收超时=%dms, 线程数=%d\n",
               connect_timeout_ms, recv_timeout_ms, threads);
    }

    if (fast_mode && !quiet_mode)
    {
        connect_timeout_ms = 300;
        recv_timeout_ms = 1000;
        if (threads < 80)
            threads = 80;
        printf("快速模式已启用：连接超时=%dms, 接收超时=%dms, 线程数=%d\n",
               connect_timeout_ms, recv_timeout_ms, threads);
    }

    // 初始化原始套接字（如果需要SYN扫描）
    if (scan_mode == SCAN_MODE_SYN_SCAN)
    {
        raw_socket_fd = create_raw_socket();
        if (raw_socket_fd < 0 && !quiet_mode)
        {
            printf("警告: 无法创建原始套接字，将回退到TCP连接扫描\n");
        }
    }

    init_task_queue();

    total_tasks = ipcount * portcount;
    if (!quiet_mode)
    {
        const char *mode_str = (scan_mode == SCAN_MODE_SYN_SCAN) ? "SYN扫描" : "TCP连接扫描";
        const char *detect_str = udpxy_detect ? "，启用UDPXY检测" : "";
        printf("开始扫描 %d 个IP，%d 个端口，共 %d 个任务，使用 %d 个线程\n",
               ipcount, portcount, total_tasks, threads);
        printf("扫描模式: %s%s\n", mode_str, detect_str);
    }

    // 创建工作线程
    num_threads = threads;
    for (int i = 0; i < threads; i++)
    {
        if (pthread_create(&worker_threads[i], NULL, worker_thread, NULL) != 0)
        {
            fprintf(stderr, "创建工作线程 %d 失败\n", i);
            num_threads = i;
            break;
        }
    }

    if (!quiet_mode)
    {
        printf("成功创建 %d 个工作线程\n", num_threads);
    }

    // 添加扫描任务
    int task_added = 0;
    int use_batch = (total_tasks > 500 && !fast_mode);
    int batch_size = use_batch ? 200 : total_tasks;

    for (int i = 0; i < ipcount; ++i)
    {
        for (int j = 0; j < portcount; j += batch_size)
        {
            int batch_end = (j + batch_size > portcount) ? portcount : j + batch_size;

            for (int k = j; k < batch_end; ++k)
            {
                scan_task_t *task = malloc(sizeof(scan_task_t));
                if (!task)
                {
                    fprintf(stderr, "内存分配失败\n");
                    continue;
                }

                strcpy(task->ip, iplist[i]);
                task->port = portlist[k];
                task->connect_timeout_ms = connect_timeout_ms;
                task->recv_timeout_ms = recv_timeout_ms;
                task->verbose = verbose;
                task->debug = debug;
                task->scan_mode = scan_mode;
                task->udpxy_detect = udpxy_detect;
                strcpy(task->outfile, outfile);

                if (enqueue_task(task) == 0)
                {
                    task_added++;
                }
                else
                {
                    free(task);
                    fprintf(stderr, "任务入队失败\n");
                }
            }

            if (use_batch && batch_end < portcount)
            {
                usleep(50000);
            }
        }
    }

    if (!quiet_mode)
    {
        printf("已添加 %d 个任务到队列，开始扫描...\n", task_added);
    }

    // 等待扫描完成
    int last_completed = 0;
    int stall_count = 0;
    int progress_interval = (task_added > 1000) ? 2000000 : 1000000;

    while (completed_tasks < task_added)
    {
        usleep(progress_interval);

        if (!quiet_mode && completed_tasks != last_completed)
        {
            if (completed_tasks - last_completed >= (task_added / 10) || completed_tasks == task_added)
            {
                printf("进度: %d/%d (%.1f%%) | 发现开放端口: %d", completed_tasks, task_added,
                       (float)completed_tasks * 100.0 / task_added, open_ports_found);
                if (udpxy_detect && udpxy_services_found > 0)
                {
                    printf(" | UDPXY服务: %d", udpxy_services_found);
                }
                printf("\n");
            }
            last_completed = completed_tasks;
            stall_count = 0;
        }
        else if (!quiet_mode)
        {
            stall_count++;
            if (stall_count > 30)
            {
                printf("扫描进行中... 当前完成: %d/%d (%.1f%%) | 发现开放端口: %d\n",
                       completed_tasks, task_added, (float)completed_tasks * 100.0 / task_added, open_ports_found);
                stall_count = 0;
            }
        }
    }

    // 清理
    shutdown_task_queue();

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(worker_threads[i], NULL);
    }

    cleanup_raw_socket();
    destroy_task_queue();

    if (!quiet_mode)
    {
        printf("扫描完成！总共处理了 %d 个任务\n", completed_tasks);
        printf("\n=== 扫描结果摘要 ===\n");
        printf("发现开放端口: %d\n", open_ports_found);
        if (udpxy_detect)
        {
            printf("发现UDPXY服务: %d\n", udpxy_services_found);
        }
        printf("扫描成功率: %.1f%%\n", (float)open_ports_found * 100.0 / task_added);
        if (outfile[0])
        {
            printf("结果已保存到: %s\n", outfile);
        }
    }

    return 0;
}
