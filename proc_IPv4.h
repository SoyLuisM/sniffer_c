#include <stdio.h>
#include "snoopy.h"
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

void *procesador_IPv4(void *datos){
    struct iphdr *eth2;
    struct sockaddr_in source,dest;

    int tuberia,long_dat;
    int size_trama;
    size_trama=-1;
    char buffer[MAX_LINES];

    tuberia = open("/tmp/mi_fifo_IPv4",O_RDONLY);

    while(1){
        long_dat=read(tuberia, &size_trama, sizeof(int ));
        printf("%d\t",size_trama);
        if(size_trama<0){
            break;
        }
        long_dat=read(tuberia, &buffer, size_trama);
        eth2 = (struct iphdr *)(buffer+(sizeof(struct ethhdr)));
        source.sin_addr.s_addr = eth2->saddr;
        dest.sin_addr.s_addr = eth2->daddr;
        printf("%s\t",inet_ntoa(dest.sin_addr));
        printf("%s\n",inet_ntoa(source.sin_addr));
    }
    pthread_exit(0);
}