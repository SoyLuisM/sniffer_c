#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
//
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>

#define MAX_LINES 65536 

int main(int argc, char *argv[]){
    if(argc == 4){
        int sock_fd;
        int puerto = atoi(argv[2]);
        char buffer[MAX_LINES];
        int size_trama;
        struct ethhdr *eth;
        struct ifreq ethreq;
        struct sockaddr server;
        int sock_size = sizeof server;

        if((sock_fd = socket(PF_INET , SOCK_RAW , IPPROTO_TCP)) < 0){
            printf("error al crear el socket\n");
            exit(-1);
        }
        //system("/sbin/ifconfig eth0 promisc");
        strncpy(ethreq.ifr_name,"eth0",IFNAMSIZ);

        ioctl(sock_fd,SIOCGIFFLAGS,&ethreq);
        ethreq.ifr_flags |= IFF_PROMISC;
        ioctl(sock_fd,SIOCSIFFLAGS,&ethreq);
        printf("hola\n");

        size_trama = recvfrom(sock_fd,(char *)buffer, MAX_LINES, 0, &server, &sock_size);

        if(size_trama<0){
            printf("error al recibir informacion\n");
            exit(-1);
        }
        printf("hola2\n");
        printf("%d\n",size_trama);

        system("sudo /sbin/ifconfig eth0 -promisc");
    }else{
        printf("Error en los parametros sintaxis\n");
        printf("./snifer Interfaz Puerto Num_paquetes\n");
    }
}