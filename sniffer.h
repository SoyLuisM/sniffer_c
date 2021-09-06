#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include<pthread.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include "snoopy.h"

int sock_fd;
struct ifreq ethreq;

void modo_promiscuo(char *interfaz, int accion){
    strncpy(ethreq.ifr_name,interfaz,IFNAMSIZ);
    ioctl(sock_fd,SIOCGIFFLAGS,&ethreq);
    
    if(accion==1){
        ethreq.ifr_flags = (ethreq.ifr_flags | IFF_PROMISC);
    }else if(accion==0){
        ethreq.ifr_flags = ethreq.ifr_flags & ~IFF_PROMISC;
    }else{
        printf("ocurrio un error\n");
    }

    if(ioctl(sock_fd,SIOCSIFFLAGS,&ethreq)){
        printf("error al activar/desactivar modo promiscuo\n");
    }
}

void *sniffer(void *datos){
    struct parametros *param;
    int tuberia;
    param = (struct parametros *)datos;

    /*variables para el socket*/
    
    char buffer[MAX_LINES];
    int size_trama;
    struct ethhdr *eth;
    
    struct sockaddr server;
    int sock_size = sizeof(server);

    /*creacion de la tuberia*/
    mkfifo("/tmp/mi_fifo",0666);
    tuberia=open("/tmp/mi_fifo",O_WRONLY);

    /*primero paso los datos necesarios al procesador de datos*/
    write(tuberia, &param, sizeof(struct parametros *));

    /*creacion del socket IPPROTO_TCP solo campura paquetes del protocolo TCP obvi*/
    //if((sock_fd = socket(PF_INET , SOCK_RAW , IPPROTO_TCP)) < 0){
    if((sock_fd = socket(PF_PACKET , SOCK_RAW , htons(ETH_P_ALL))) < 0){
        printf("error al crear el socket\n");
        exit(-1);
    }

     /*configuracion de la targeta en modo promiscuo*/
    //system("/sbin/ifconfig eth0 promisc");
    modo_promiscuo(param->interfaz,1);

    /*este ciclo captura los paquetes*/
    for(int i=0; i<param->n_paquetes; i++){
        /*captura de la trama*/
        size_trama = recvfrom(sock_fd,(char *)buffer, MAX_LINES, 0, (struct sockaddr *)&server, &sock_size);
        if(size_trama<0){
            printf("error al recibir informacion\n");
            exit(-1);
        }
        /*escrituta en el socket*/
        write(tuberia, buffer, MAX_LINES);
    }
    //close(sock_fd);
    /*desactivando modo promiscuo*/
    modo_promiscuo(param->interfaz,0);

    //system("sudo /sbin/ifconfig eth0 -promisc");
    close(tuberia);
    pthread_exit(0);
}