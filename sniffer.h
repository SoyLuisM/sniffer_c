#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include<pthread.h>
#include "snoopy.h"

/*el tamaño maximo de la trama ethernet es 1518 bytes
dejo este valor nomas por que si*/
#define MAX_LINES 65536 

void *sniffer(void *datos){
    struct parametros *param;

    param = (struct parametros *)datos;

    printf("hola soy el sniffer %s %d\n",param->interfaz,param->n_paquetes);
    pthread_exit(0);
}
// int main(int argc, char *argv[]){

//         /*variables para el socket*/
//         int sock_fd;
//         char buffer[MAX_LINES];
//         int size_trama;
//         struct ethhdr *eth;
//         struct ifreq ethreq;
//         struct sockaddr server;
//         int sock_size = sizeof(server);
//         /*variables para el archivo*/
//         FILE *fichero,*fichero2;
//         fichero=fopen("sniffer.log","w");
//         fichero2=fopen("sniffer2.log","w");
//         /*otras variables*/
//         int total_paquetes = atoi(argv[2]);
        
//         /*creacion del socket IPPROTO_TCP solo campura paquetes del protocolo TCP obvi*/
//         //if((sock_fd = socket(PF_INET , SOCK_RAW , IPPROTO_TCP)) < 0){
//         //if((sock_fd = socket(PF_INET , SOCK_RAW , ETH_P_ALL)) < 0){
//         if((sock_fd = socket(PF_PACKET , SOCK_RAW , htons(ETH_P_ALL))) < 0){
//             printf("error al crear el socket\n");
//             exit(-1);
//         }
        
//         /*configuracion de la targeta en modo promiscuo*/

//         //system("/sbin/ifconfig eth0 promisc");
//         strncpy(ethreq.ifr_name,argv[1],IFNAMSIZ);

//         ioctl(sock_fd,SIOCGIFFLAGS,&ethreq);
//         ethreq.ifr_flags |= IFF_PROMISC;
//         ioctl(sock_fd,SIOCSIFFLAGS,&ethreq);

//         fprintf(fichero,"ip destino\tip origen\t protocolo\n");
//         for(int i=0; i<total_paquetes; i++){
//             /*captura de la trama*/
//             size_trama = recvfrom(sock_fd,(char *)buffer, MAX_LINES, 0, (struct sockaddr *)&server, &sock_size);
//             if(size_trama<0){
//                 printf("error al recibir informacion\n");
//                 exit(-1);
//             }
//             eth = (struct ethhdr *)buffer;

//             //escritura en el fichero
//             if(htons(eth->h_proto)== 0x0800){
//                 fprintf(fichero, "%02X.%02x.%02x.%02x.%02x.%02x\t",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
//                 fprintf(fichero, "%02x.%02x.%02x.%02x.%02x.%02x\t",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
//                 fprintf(fichero,"%x\n",htons(eth->h_proto));
//             }else{
//                 fprintf(fichero2, "%02x.%02x.%02x.%02x.%02x.%02x\t",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
//                 fprintf(fichero2, "%02x.%02x.%02x.%02x.%02x.%02x\t",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
//                 fprintf(fichero2,"%x\n",htons(eth->h_proto));
//             }
//         }

//         /*debo cerrar los sockets y archivos*/
//         fclose(fichero);
//         fclose(fichero2);
//         //close(sock_fd);

//         system("sudo /sbin/ifconfig eth0 -promisc");
//     
// }