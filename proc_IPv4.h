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

void guardar_datos(FILE *file, struct iphdr *eth2, int long_dat){
    struct sockaddr_in source,dest;
    source.sin_addr.s_addr = eth2->saddr;
    dest.sin_addr.s_addr = eth2->daddr;
    fprintf(file,"%s\t",inet_ntoa(dest.sin_addr));
    fprintf(file,"%s\t",inet_ntoa(source.sin_addr));
    fprintf(file,"%d\n",(unsigned int)eth2->protocol);
}

/*esta es la funcion pricipal encargada de procesar los datos del protocolo IPv4*/
void *procesador_IPv4(void *datos){
    struct iphdr *eth2;
    struct sockaddr_in source,dest;
    FILE *f_icmpv4, *f_igmp, *f_ip, *f_tcp, *f_udp, *f_ipv6, *f_ospf; 
    int c_icmpv4=0, c_igmp=0, c_ip=0, c_tcp=0, c_udp=0, c_ipv6=0, c_ospf=0,total=0,descartados=0;
    f_icmpv4=fopen("IPv4_icmpv4.log","w");
    f_igmp=fopen("IPv4_igmp.log","w");
    f_ip=fopen("IPv4_ip.log","w");
    f_tcp=fopen("IPv4_tcp.log","w");
    f_udp=fopen("IPv4_udp.log","w");
    f_ipv6=fopen("IPv4_ipv6.log","w");
    f_ospf=fopen("IPv4_ospf.log","w");

    int tuberia,long_dat;
    int size_trama;
    size_trama=-1;
    char buffer[MAX_LINES];

    tuberia = open("/tmp/mi_fifo_IPv4",O_RDONLY);

    while(1){
        long_dat=read(tuberia, &size_trama, sizeof(int ));
        if(size_trama<0){
            break;
        }
        long_dat=read(tuberia, &buffer, size_trama);
        eth2 = (struct iphdr *)(buffer+(sizeof(struct ethhdr)));

        if(eth2->protocol== 1){
            guardar_datos(f_icmpv4, eth2, size_trama);
            c_icmpv4++;
        }else if(eth2->protocol== 2){
            guardar_datos(f_igmp, eth2, size_trama);
            c_igmp++;
        }else if(eth2->protocol== 4){
            guardar_datos(f_ip, eth2, size_trama);
            c_ip++;
        }else if(eth2->protocol== 6){
            guardar_datos(f_tcp, eth2, size_trama);
            c_tcp++;
        }else if(eth2->protocol== 11){
            guardar_datos(f_udp, eth2, size_trama);
            c_udp++;
        }else if(eth2->protocol== 29){
            guardar_datos(f_ipv6, eth2, size_trama);
            c_ipv6++;
        }else if(eth2->protocol== 59){
            guardar_datos(f_ospf, eth2, size_trama);
            c_ospf++;
        }else{
            descartados++;
        }
        total++;
       
    }
    close(f_icmpv4);
    close(f_igmp);
    close(f_ip);
    close(f_tcp);
    close(f_udp);
    close(f_ipv6);
    close(f_ospf);

    FILE *f_resultados =fopen("IPv4_resultados.log","w");
    fprintf(f_resultados,"\t\t\tResultados del analizis\n\n\n");
    fprintf(f_resultados,"Total paquetes analizados %d\n\n",total);
    fprintf(f_resultados,"Descripcion de los paquetes analizados: \n");
    fprintf(f_resultados,"icmp: %d\tigmp: %d\tip: %d\ttcp: %d\tudp: %d\tipv6: %d\tospf: %d\t descartados: %d\n",c_icmpv4, c_igmp, c_ip, c_tcp, c_udp, c_ipv6, c_ospf,descartados);
    close(f_resultados);
    pthread_exit(0);
}