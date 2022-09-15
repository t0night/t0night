## 0x01 用途

当连接到一个没有dhcp的网络时，需要猜测正确的网段。手动配置网络效率较低，该工具实现自动化配置网络，配置成功之后进行该网段扫描。



## 0x02 环境

开发环境为ubuntu22.04，需要一个路由器设备，将路由器的dhcp服务关闭，如下所示：

![image-20220915151634901](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20220915151634901.png)

## 0x03 源码

已经封装好删除现有路由和添加路由的函数，需要时直接调用即可。

```c
//gcc guess_net.c -o guess_net
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <error.h>
#include <unistd.h>
#include <fcntl.h>


#define GLOBAL_MASK "255.255.255.0"
#define IP_prefix "192.168."
#define DEVICES "enp0s5"

struct route_rule
{
    char *Iface;
    char *Destination;
    char *Gateway;
    char *Flags;
    char *RefCnt;
    char *Use;
    char *Metric;
    char *Mask;
    char *MTU;
    char *Window;
    char *IRTT;
};


// int del_route(char *DeviceName,char *IP,char *Netmask,char *Gateway){
//     int fd;
//     fd = socket(AF_INET, SOCK_DGRAM, 0);
//     struct rtentry route;
//     struct sockaddr_in *addr;
//     memset(&route, 0, sizeof(route));

//     addr = (struct sockaddr_in*)&route.rt_dst;
//     addr->sin_family = AF_INET;
//     addr->sin_addr.s_addr = inet_addr(IP);

//     addr = (struct sockaddr_in*)&route.rt_gateway;
//     addr->sin_family = AF_INET;
//     addr->sin_addr.s_addr = inet_addr(Gateway);

//     addr = (struct sockaddr_in*)&route.rt_genmask;
//     addr->sin_family = AF_INET;
//     addr->sin_addr.s_addr = inet_addr(Netmask);

//     route.rt_flags = RTF_UP | RTF_GATEWAY;
//     route.rt_dev = DeviceName;

//     if(ioctl(fd, SIOCDELRT, route)<0)
//     {
//         perror("delete route error!!");
//         return 0;
//     }
//     return 1;
// }
int del_route(char *ipAddr, char *mask,char *gateWay,char* devName)
{
  int fd;
  int rc = 0;
  struct sockaddr_in _sin;
  struct sockaddr_in *sin = &_sin;
  struct rtentry  rt;
 
  do
  {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
      printf("addRoute: socket   error\n");
      rc = -1;
      break;
    }
    //网关  
    memset(&rt, 0, sizeof(struct rtentry));
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    if(inet_aton(gateWay, &sin->sin_addr)<0)
    {
      printf( "addRoute:  gateWay inet_aton error\n" );
      rc = -2;
      break;
    }
    memcpy ( &rt.rt_gateway, sin, sizeof(struct sockaddr_in));
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family=AF_INET;
    if(inet_aton(ipAddr, &((struct sockaddr_in *)&rt.rt_dst)->sin_addr)<0)
    {
      printf( "addRoute:  dst inet_aton error\n" );
      rc = -3;
      break;
    }
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family=AF_INET;
    if(inet_aton(mask, &((struct sockaddr_in *)&rt.rt_genmask)->sin_addr)<0)
    {
      printf( "addRoute:  mask inet_aton error\n" );
      rc = -4;
      break;
    }
 
    if(devName)
      rt.rt_dev = devName;
    rt.rt_flags = RTF_UP|RTF_GATEWAY;
    if (ioctl(fd, SIOCDELRT, &rt)<0)
    {
        perror("del");
        printf( "delete route error!!\n");
        rc = -5;
    }
  }while(0);
  close(fd);
  return rc;
}

int add_route(char *ipAddr, char *mask,char *gateWay,char* devName)
{
  int fd;
  int rc = 0;
  struct sockaddr_in _sin;
  struct sockaddr_in *sin = &_sin;
  struct rtentry  rt;
 
  do
  {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
      printf("addRoute: socket   error\n");
      rc = -1;
      break;
    }
    //网关  
    memset(&rt, 0, sizeof(struct rtentry));
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    if(inet_aton(gateWay, &sin->sin_addr)<0)
    {
      printf( "addRoute:  gateWay inet_aton error\n" );
      rc = -2;
      break;
    }
    memcpy ( &rt.rt_gateway, sin, sizeof(struct sockaddr_in));
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family=AF_INET;
    if(inet_aton(ipAddr, &((struct sockaddr_in *)&rt.rt_dst)->sin_addr)<0)
    {
      printf( "addRoute:  dst inet_aton error\n" );
      rc = -3;
      break;
    }
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family=AF_INET;
    if(inet_aton(mask, &((struct sockaddr_in *)&rt.rt_genmask)->sin_addr)<0)
    {
      printf( "addRoute:  mask inet_aton error\n" );
      rc = -4;
      break;
    }
 
    if(devName)
      rt.rt_dev = devName;
    rt.rt_flags = RTF_UP;
    // printf("flag:%d\n",rt.rt_flags);
    // exit(0);
    if (ioctl(fd, SIOCADDRT, &rt)<0)
    {
      perror( "add route error!!\n");
      rc = -5;
    }
  }while(0);
  close(fd);
  return rc;
}

void del_all_route(char *device){
    FILE *fd = fopen("/proc/net/route","r");
    int data_len = 0x100;
    char *data = malloc(data_len);
    char *tmp=NULL;
    struct route_rule rr;
    struct in_addr Des_netAddr,Gw_netAddr,Mask_netAddr;
    if(fd<0){
        perror("open error");
        exit(-1);
    }
    while(fgets(data,data_len,fd)!=NULL){
        if(strstr(data,"Iface")&&strstr(data,"Destination")){
            //判断是否为第一行
            continue;
        }
        puts("------------");
        rr.Iface = strtok(data,"\t");
        rr.Destination = strtok(NULL, "\t");
        rr.Gateway = strtok(NULL, "\t");
        rr.Flags = strtok(NULL, "\t");
        rr.RefCnt = strtok(NULL, "\t");
        rr.Use = strtok(NULL, "\t");
        rr.Metric = strtok(NULL, "\t");
        rr.Mask = strtok(NULL, "\t");
        rr.MTU = strtok(NULL, "\t");
        rr.Window = strtok(NULL, "\t");
        rr.IRTT = strtok(NULL, "\t");
            // printf("iface:%s\n",rr.Iface);

        if(!strcmp(rr.Iface,device)){
            printf("iface:%s\n",rr.Iface);
            Des_netAddr.s_addr = strtol(rr.Destination,&tmp,16);
            printf("Destination:%s\n",inet_ntoa(Des_netAddr));
            Gw_netAddr.s_addr = strtol(rr.Gateway,&tmp,16);
            printf("Gateway:%s\n",inet_ntoa(Gw_netAddr));
            Mask_netAddr.s_addr = strtol(rr.Mask,&tmp,16);
            printf("Mask:%s\n",inet_ntoa(Mask_netAddr));
            del_route(inet_ntoa(Des_netAddr),inet_ntoa(Mask_netAddr),inet_ntoa(Gw_netAddr),device);
        }
    }
}
int SetIfAddr( char *Ipaddr, char *mask,char *ifname)//char *gateway
{
    int fd;
    int rc;
    struct ifreq ifr; 
    struct sockaddr_in *sin;
    struct rtentry  rt;
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
            perror("socket   error");     
            return -1;     
    }
    memset(&ifr,0,sizeof(ifr)); 
    strcpy(ifr.ifr_name,ifname); 
    sin = (struct sockaddr_in*)&ifr.ifr_addr;     
    sin->sin_family = AF_INET;     
    //IP地址
    if(inet_aton(Ipaddr,&(sin->sin_addr)) < 0)   
    {     
        perror("inet_aton   error");     
        return -2;     
    }    
 
    if(ioctl(fd,SIOCSIFADDR,&ifr) < 0)   
    {     
        perror("ioctl   SIOCSIFADDR   error");     
        return -3;     
    }
    //子网掩码
    if(inet_aton(mask,&(sin->sin_addr)) < 0)   
    {     
        perror("inet_pton   error");     
        return -4;     
    }    
    if(ioctl(fd, SIOCSIFNETMASK, &ifr) < 0)
    {
        perror("ioctl");
        return -5;
    }    
    close(fd); 
    return rc;
}

int main()
{
    char cmd[0x100];
    char ip[0x20];
    int i;
    for(i=0;i<0x10;i++){
        sprintf(ip,"%s%d.%d",IP_prefix,i,rand()%10+100);
        printf("\n\033[0m\033[1;31m+---------\t 设置IP为:%s \t------------------------------------------+\033[0m\n",ip);
        SetIfAddr(ip,GLOBAL_MASK,DEVICES);
        sprintf(cmd,"./fscan_amd64 -h %s/24 -nopoc -nobr -hn %s",ip,ip);
        printf("[+] 开始扫描:%s\n",cmd);
        system(cmd);
    }
    // del_all_route("enp0s5");
    // add_route("192.168.5.0","255.255.255.0","","enp0s5");
    return 0;
}
/*
查询路由表：/proc/net/route
添加路由表：
解决了gw为0.0.0.0时不可添加：https://blog.csdn.net/qq_39642794/article/details/102775620
*/
```



## 0x04 效果

我在192.168.5.0和192.168.8.0网段下各留了一台存活主机，通过运行结果可以看出是能够扫描到的。

![image-20220915152027166](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20220915152027166.png)