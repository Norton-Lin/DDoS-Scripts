/* NTP Scanner */
 
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
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
 
volatile int running_threads = 0;           // 正在运行的线程数
volatile int found_srvs = 0;                // 找到的NTP服务器数量
volatile unsigned long per_thread = 0;      // 每个线程扫描的个数
volatile unsigned long start = 0;           // 起始IP
volatile unsigned long scanned = 0;         
volatile int sleep_between = 0;             // 发送数据包间的间隔
volatile int bytes_sent = 0;                // 发送的字节数
volatile unsigned long hosts_done = 0;      //  完成扫描的主机数量
FILE *fd;
char payload[] =
"\x17\x00\x03\x2A\x00\x00\x00\x00";
 
size = sizeof(payload);
 
 // 发送NTP请求的线程函数
void *flood(void *par1)
{
    running_threads++;
    int thread_id = (int)par1;
    unsigned long start_ip = htonl(ntohl(start)+(per_thread*thread_id));    // 初始化起始-终止ip地址
    unsigned long end = htonl(ntohl(start)+(per_thread*(thread_id+1)));
    unsigned long w;
    int y;
    unsigned char buf[65536];
    memset(buf, 0x01, 8);
    int sizeofpayload = 8;
    int sock;
    if((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))<0) {     // 创建UDP套接字
        perror("cant open socket");
        exit(-1);
    }
    // 遍历起始IP-终止IP发送NTP请求payload
    for(w=ntohl(start_ip);w<htonl(end);w++)                                        // struct sockaddr_in
    {                                                                              // { 
        struct sockaddr_in servaddr;                                               //      sa_family_t     sin_family;      // 地址族(Address Family)
        bzero(&servaddr, sizeof(servaddr));                                        //      unit16_t        sin_port;        // 16位TCP/UDP 端口号
        servaddr.sin_family = AF_INET;       // IPv4                               //      struct in_addr  sin_addr;        // 32位IP地址
        servaddr.sin_addr.s_addr=htonl(w);                                         //      char            sin_zero[8];     // 不使用
        servaddr.sin_port=htons(123);        // UDP端口号默认为123                  // };
        sendto(sock,payload,size,0, (struct sockaddr *)&servaddr,sizeof(servaddr));         // 发送NTP请求
        bytes_sent+=size;
        scanned++;
        hosts_done++;
    }
    close(sock);        //关闭套接字
    running_threads--;
    return;
}
 
void sighandler(int sig)
{
    fclose(fd);
    printf("\n");
    exit(0);
}

// 监听网络上的NTP响应并进行处理
void *recievethread()
{
    printf("\n");
    int saddr_size, data_size, sock_raw;
    struct sockaddr_in saddr;
    struct in_addr in;
 
    unsigned char *buffer = (unsigned char *)malloc(65536);     // 存储接收到的数据包
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_UDP);        // 创建套接字来监听UDP数据包
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        exit(1);
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , (struct sockaddr *)&saddr , &saddr_size);      // 从套接字接受数据包
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            exit(1);
        }
        struct iphdr *iph = (struct iphdr*)buffer;                          // 将缓冲区的首地址转换为IP头结构体的指针，以便解析IP头信息
        if(iph->protocol == 17)     // 17为UDP协议标识
        {
            unsigned short iphdrlen = iph->ihl*4;                           // 计算IP头长度
            struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen);      // 跳过IP头，将缓冲区地址转为UDP头
            unsigned char* payload = buffer + iphdrlen + 8;                 // 跳过UDP头，指向有效载荷payload
            if(ntohs(udph->source) == 123)                                  // 检查是否为NTP默认端口
            {
                int body_length = data_size - iphdrlen - 8;
 
                if (body_length > 40)
 
                {
                // 发现一个NTP服务器， 并将其IP地址和响应长度写入文件
                found_srvs++;
 
                fprintf(fd,"%s %d\n",inet_ntoa(saddr.sin_addr),body_length);
                fflush(fd);
 
                }
 
            }
        }
 
    }
    close(sock_raw);
 
}
 
int main(int argc, char *argv[ ])
{
 
    if(argc < 6){
                fprintf(stderr, "Invalid parameters!\n");
        fprintf(stdout, "Shrooms NTP Scanner\nUsage: %s <ip range start (1.0.0.0)> <ip range end (255.255.255.255)> <outfile> <threads> <scan delay in ms>\n", argv[0]);
        exit(-1);
    }
    fd = fopen(argv[3], "a");
    sleep_between = atoi(argv[5]);
 
    signal(SIGINT, &sighandler);
 
    int threads = atoi(argv[4]);
    pthread_t thread;
 
    pthread_t listenthread;
    pthread_create( &listenthread, NULL, &recievethread, NULL);
 
    char *str_start = malloc(18);
    memset(str_start, 0, 18);
    str_start = argv[1];
    char *str_end = malloc(18);
    memset(str_end, 0, 18);
    str_end = argv[2];
    start = inet_addr(str_start);
    per_thread = (ntohl(inet_addr(str_end)) - ntohl(inet_addr(str_start))) / threads;
    unsigned long toscan = (ntohl(inet_addr(str_end)) - ntohl(inet_addr(str_start)));
    int i;
    for(i = 0;i<threads;i++){
        pthread_create( &thread, NULL, &flood, (void *) i);
    }
    sleep(1);
    printf("Scan in Progress \n");
    char *temp = (char *)malloc(17);
    memset(temp, 0, 17);
    sprintf(temp, "NTP Found");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "IP/s");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Bytes/s");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Threads");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Percent Done");
    printf("%s", temp);
    printf("\n");
 
    char *new;
    new = (char *)malloc(16*6);
    while (running_threads > 0)
    {
        printf("\r");
        memset(new, '\0', 16*6);
        sprintf(new, "%s|%-15lu", new, found_srvs);
        sprintf(new, "%s|%-15d", new, scanned);
        sprintf(new, "%s|%-15d", new, bytes_sent);
        sprintf(new, "%s|%-15d", new, running_threads);
        memset(temp, 0, 17);
        int percent_done=((double)(hosts_done)/(double)(toscan))*100;
        sprintf(temp, "%d%%", percent_done);
        sprintf(new, "%s|%s", new, temp);
        printf("%s", new);
        fflush(stdout);
        bytes_sent=0;
        scanned = 0;
        sleep(1);
    }
    printf("\n");
    fclose(fd);
    return 0;
}