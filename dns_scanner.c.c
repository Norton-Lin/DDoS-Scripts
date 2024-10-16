#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <math.h>
#include <stropts.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// DNS头部结构体定义
struct DNS_HEADER
{
    unsigned short id; // 标识号

    unsigned char rd : 1;     // Recursion Desired 期望递归查询
    unsigned char tc : 1;     // Truncated Message 消息被截断
    unsigned char aa : 1;     // Authoritative Answer 权威答案
    unsigned char opcode : 4; // Purpose of Message 消息用途
    unsigned char qr : 1;     // Query/Response Flag 查询/响应标志

    unsigned char rcode : 4; // Response Code 响应码
    unsigned char cd : 1;    // Checking Disabled 禁止检查
    unsigned char ad : 1;    // Authenticated Data 经认证的数据
    unsigned char z : 1;     // Z, Reserved 保留位
    unsigned char ra : 1;    // Recursion Available 递归可用

    unsigned short q_count;    // Number of Question Entries 问题条目数
    unsigned short ans_count;  // Number of Answer Entries 答案条目数
    unsigned short auth_count; // Number of Authority Entries 权威条目数
    unsigned short add_count;  // Number of Additional Entries 附加条目数
};

// 问题记录结构体定义
struct QUESTION
{
    unsigned short qtype;  // 类型
    unsigned short qclass; // 类别
};

#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;     // 类型
    unsigned short _class;   // 类别
    unsigned int ttl;        // 生存时间
    unsigned short data_len; // 数据长度
};
#pragma pack(pop)

// 解析记录结构体定义
struct RES_RECORD
{
    unsigned char *name;     // 名称
    struct R_DATA *resource; // 资源数据
    unsigned char *rdata;    // 解析数据
};

// 查询结构体定义
typedef struct
{
    unsigned char *name;   // 名称
    struct QUESTION *ques; // 问题记录
} QUERY;

// 全局变量定义
volatile int running_threads = 0;      // 当前线程数
volatile int found_srvs = 0;           // 找到的服务数量
volatile unsigned long per_thread = 0; // 每个线程负责的IP范围
volatile unsigned long start = 0;      // 开始扫描的IP地址
volatile unsigned long scanned = 0;    // 已扫描的IP数量
volatile int sleep_between = 0;        // 线程之间睡眠时间（毫秒）
volatile int bytes_sent = 0;           // 发送的字节数
volatile unsigned long hosts_done = 0; // 完成扫描的主机数量
FILE *fd;                              // 文件描述符

// 将域名转换为DNS格式
void ChangetoDnsNameFormat(unsigned char *dns, unsigned char *host)
{
    int lock = 0, i;
    strcat((char *)host, ".");

    for (i = 0; i < strlen((char *)host); i++) // 遍历域名
    {
        if (host[i] == '.') // 如果遇到'.'字符
        {
            *dns++ = i - lock;       // 存储标签长度
            for (; lock < i; lock++) // 复制标签内容
            {
                *dns++ = host[lock]; // 复制域名字符
            }
            lock++; // 更新锁位置
        }
    }
    *dns++ = '\0'; // 结束标签
}

// 多线程发送DNS请求
void *flood(void *par1)
{
    running_threads++;                                                        // 增加正在运行的线程数
    int thread_id = (int)par1;                                                // 获取线程ID
    unsigned long start_ip = htonl(ntohl(start) + (per_thread * thread_id));  // 计算开始IP
    unsigned long end = htonl(ntohl(start) + (per_thread * (thread_id + 1))); // 计算结束IP
    unsigned long w;
    int y;
    unsigned char *host = (unsigned char *)malloc(50); // 分配内存存储主机名
    strcpy((char *)host, ".");                         // 初始化主机名为根域
    unsigned char buf[65536], *qname;
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
    dns = (struct DNS_HEADER *)&buf; // 指向DNS头部

    // 设置DNS头部字段
    dns->id = (unsigned short)htons(rand());                  // 设置事务ID
    dns->qr = 0;                                              // 设置为查询模式
    dns->opcode = 0;                                          // 设置操作码为标准查询
    dns->aa = 0;                                              // 设置非权威回答
    dns->tc = 0;                                              // 设置非截断消息
    dns->rd = 1;                                              // 请求递归解析
    dns->ra = 0;                                              // 不指示递归能力
    dns->z = 0;                                               // 保留位
    dns->ad = 0;                                              // 不标记认证数据
    dns->cd = 0;                                              // 不禁用检查
    dns->rcode = 0;                                           // 设置无错误状态
    dns->q_count = htons(1);                                  // 设置一个问题记录
    dns->ans_count = 0;                                       // 设置答案记录数为0
    dns->auth_count = 0;                                      // 设置权威记录数为0
    dns->add_count = htons(1);                                // 设置附加记录数为1
    qname = (unsigned char *)&buf[sizeof(struct DNS_HEADER)]; // 指向DNS问题名称部分

    // 转换主机名为DNS格式
    ChangetoDnsNameFormat(qname, host);
    qinfo = (struct QUESTION *)&buf[sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1)]; // 指向DNS问题记录部分

    // 设置问题记录字段
    qinfo->qtype = htons(255); // 设置查询类型为ANY
    qinfo->qclass = htons(1);  // 设置查询类为IN

    // 设置EDNS扩展字段
    void *edns = (void *)qinfo + sizeof(struct QUESTION) + 1;
    memset(edns, 0x00, 1);     // 设置版本号为0
    memset(edns + 1, 0x29, 1); // 设置EDNS0标志
    memset(edns + 2, 0xFF, 2); // 设置最大UDP有效载荷为65499
    memset(edns + 4, 0x00, 7); // 保留字段

    // 获取有效载荷大小
    int sizeofpayload = sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1) + sizeof(struct QUESTION) + 11;
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) // 创建UDP套接字
    {
        perror("cant open socket");
        exit(-1);
    }

    // 循环发送DNS请求
    for (w = ntohl(start_ip); w < htonl(end); w++) // 遍历指定的IP范围
    {
        struct sockaddr_in servaddr;
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(w);                                                         // 设置目标IP地址
        servaddr.sin_port = htons(53);                                                               // 设置DNS端口
        sendto(sock, (char *)buf, sizeofpayload, 0, (struct sockaddr *)&servaddr, sizeof(servaddr)); // 发送DNS请求
        bytes_sent += 24;                                                                            // 记录发送的字节数
        scanned++;                                                                                   // 记录已扫描的IP数量
        hosts_done++;                                                                                // 记录已完成扫描的主机数量
        usleep(sleep_between * 1000);                                                                // 休眠指定时间
    }
    close(sock);       // 关闭套接字
    running_threads--; // 减少正在运行的线程数
    return NULL;
}

// 信号处理函数
void sighandler(int sig)
{
    fclose(fd);
    printf("\n");
    exit(0);
}

// 接收线程
void recievethread()
{
    printf("Started Listening Thread\n");
    int saddr_size, data_size, sock_raw;
    struct sockaddr_in saddr;
    struct in_addr in;

    unsigned char *buffer = (unsigned char *)malloc(65536); // 分配缓冲区内存
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);      // 创建原始套接字
    if (sock_raw < 0)
    {
        printf("Socket Error\n");
        exit(1);
    }

    // 循环接收UDP数据包
    while (1)
    {
        saddr_size = sizeof saddr;
        data_size = recvfrom(sock_raw, buffer, 65536, 0, (struct sockaddr *)&saddr, &saddr_size); // 接收数据包
        if (data_size < 0)
        {
            printf("Recvfrom error, failed to get packets\n");
            exit(1);
        }

        struct iphdr *iph = (struct iphdr *)buffer;
        if (iph->protocol == 17) // 如果是UDP协议
        {
            unsigned short iphdrlen = iph->ihl * 4;                     // 计算IP头部长度
            struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen); // 获取UDP头部
            unsigned char *payload = buffer + iphdrlen + 8;             // 获取有效载荷
            if (ntohs(udph->source) == 53)                              // 如果源端口为53（DNS）
            {
                int body_length = data_size - iphdrlen - 8; // 计算有效载荷长度
                struct DNS_HEADER *dns = (struct DNS_HEADER *)payload;
                if (dns->ra == 1) // 如果递归可用
                {
                    found_srvs++;                                                     // 记录找到的服务数量
                    fprintf(fd, "%s . %d\n", inet_ntoa(saddr.sin_addr), body_length); // 记录响应信息
                    fflush(fd);
                }
            }
        }
    }
    close(sock_raw); // 关闭套接字
}

// 主函数
int main(int argc, char *argv[])
{
    if (argc < 6)
    {
        fprintf(stderr, "Invalid parameters!\n");
        fprintf(stdout, "Usage: %s <class a start> <class a end> <outfile> <threads> <scan delay in ms>\n", argv[0]); // 参数帮助信息
        exit(-1);
    }
    fd = fopen(argv[3], "a");      // 打开输出文件
    sleep_between = atoi(argv[5]); // 设置扫描间隔时间

    signal(SIGINT, &sighandler); // 注册信号处理函数

    int threads = atoi(argv[4]); // 设置线程数
    pthread_t thread;

    // 创建监听线程
    pthread_t listenthread;
    pthread_create(&listenthread, NULL, &recievethread, NULL);

    // 分配内存并初始化起始和结束IP地址字符串
    char *str_start = malloc(18);
    memset(str_start, 0, 18);
    str_start = strcat(str_start, argv[1]);
    str_start = strcat(str_start, ".0.0.0");
    char *str_end = malloc(18);
    memset(str_end, 0, 18);
    str_end = strcat(str_end, argv[2]);
    str_end = strcat(str_end, ".255.255.255");

    // 将字符串转换为数值型IP地址
    start = inet_addr(str_start);
    per_thread = (ntohl(inet_addr(str_end)) - ntohl(inet_addr(str_start))) / threads; // 计算每个线程的IP范围
    unsigned long toscan = (ntohl(inet_addr(str_end)) - ntohl(inet_addr(str_start))); // 计算总的待扫描IP数量

    int i;
    for (i = 0; i < threads; i++) // 创建并启动线程
    {
        pthread_create(&thread, NULL, &flood, (void *)i);
    }
    sleep(1);                     // 等待一段时间
    printf("Starting Scan...\n"); // 打印开始扫描信息

    // 初始化打印格式
    char *temp = (char *)malloc(17);
    memset(temp, 0, 17);
    sprintf(temp, "Found"); // 格式化输出标题
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Host/s");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "B/s");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Running Thrds");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Done");
    printf("%s", temp);
    printf("\n");

    char *new;
    new = (char *)malloc(16 * 6);
    while (running_threads > 0) // 循环打印扫描进度
    {
        printf("\r");
        memset(new, '\0', 16 * 6);
        sprintf(new, "%s|%-15lu", new, found_srvs);     // 找到的服务数量
        sprintf(new, "%s|%-15d", new, scanned);         // 扫描的IP数量
        sprintf(new, "%s|%-15d", new, bytes_sent);      // 发送的字节数
        sprintf(new, "%s|%-15d", new, running_threads); // 运行中的线程数
        memset(temp, 0, 17);
        int percent_done = ((double)(hosts_done) / (double)(toscan)) * 100; // 计算完成百分比
        sprintf(temp, "%d%%", percent_done);
        sprintf(new, "%s|%s", new, temp); // 完成百分比
        printf("%s", new);
        fflush(stdout);
        bytes_sent = 0; // 清零发送字节数
        scanned = 0;    // 清零扫描的IP数量
        sleep(1);       // 等待一秒
    }
    printf("\n");
    fclose(fd); // 关闭文件
    return 0;
}