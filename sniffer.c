#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
//
// #include <sys/types.h>
// #include <netdb.h>
// #include <unistd.h>

/*el tamaño maximo de la trama ethernet es 1518 bytes
dejo este valor nomas por que si*/
#define MAX_LINES 65536 

int main(int argc, char *argv[]){
    if(argc == 3){
        /*variables para el socket*/
        int sock_fd;
        char buffer[MAX_LINES];
        int size_trama;
        struct ethhdr *eth;
        struct ifreq ethreq;
        struct sockaddr server;
        int sock_size = sizeof(server);
        /*variables para el archivo*/
        FILE *fichero;
        fichero=fopen("sniffer.log","w");
        
        /*creacion del socket IPPROTO_TCP solo campura paquetes del protocolo TCP obvi*/
        //if((sock_fd = socket(PF_INET , SOCK_RAW , IPPROTO_TCP)) < 0){
        //if((sock_fd = socket(PF_INET , SOCK_RAW , ETH_P_ALL)) < 0){
        if((sock_fd = socket(PF_PACKET , SOCK_RAW , htons(ETH_P_ALL))) < 0){
            printf("error al crear el socket\n");
            exit(-1);
        }
        
        /*configuracion de la targeta en modo promiscuo*/

        //system("/sbin/ifconfig eth0 promisc");
        strncpy(ethreq.ifr_name,argv[1],IFNAMSIZ);

        ioctl(sock_fd,SIOCGIFFLAGS,&ethreq);
        ethreq.ifr_flags |= IFF_PROMISC;
        ioctl(sock_fd,SIOCSIFFLAGS,&ethreq);

        /*captura de la trama*/
        size_trama = recvfrom(sock_fd,(char *)buffer, MAX_LINES, 0, (struct sockaddr *)&server, &sock_size);

        //escritura en el fichero
        fprintf(fichero, "%s\n",buffer);
        fclose(fichero);

        if(size_trama<0){
            printf("error al recibir informacion\n");
            exit(-1);
        }

        printf("%d\n",size_trama);

        /*debo cerrar los sockets*/
        close(sock_fd);

        system("sudo /sbin/ifconfig eth0 -promisc");
    }else{
        printf("Error en los parametros sintaxis\n");
        printf("./snifer Interfaz Num_paquetes\n");
    }
}