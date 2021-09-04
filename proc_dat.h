#include <stdio.h>
#include "snoopy.h"
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include <linux/if_ether.h>

void *procesar_datos(void *datos){
    FILE *fichero,*fichero2,*fichero3;
    fichero=fopen("sniffer.log","w");
    fichero2=fopen("sniffer2.log","w");
    fichero3=fopen("sniffer3.log","w");
    
    struct parametros *param;
    int tuberia, long_dat;
    struct ethhdr *eth;
    char buffer[MAX_LINES];
    tuberia = open("/tmp/mi_fifo",O_RDONLY);

    long_dat=read(tuberia, &param, sizeof(struct parametros *));

    for(int i = 0; i<param->n_paquetes;i++ ){
        long_dat=read(tuberia, buffer, MAX_LINES);
        eth = (struct ethhdr *)buffer;
        if(htons(eth->h_proto) ==0x0800){
            fprintf(fichero,"%02X.%02x.%02x.%02x.%02x.%02x\t",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
            fprintf(fichero,"%02x.%02x.%02x.%02x.%02x.%02x\t",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
            fprintf(fichero,"%x\n",htons(eth->h_proto));
        }else if(htons(eth->h_proto) ==0x86DD){
            fprintf(fichero2,"%02X.%02x.%02x.%02x.%02x.%02x\t",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
            fprintf(fichero2,"%02x.%02x.%02x.%02x.%02x.%02x\t",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
            fprintf(fichero2,"%x\n",htons(eth->h_proto));
        }else if(htons(eth->h_proto) ==0x0806){
            fprintf(fichero3,"%02X.%02x.%02x.%02x.%02x.%02x\t",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
            fprintf(fichero3,"%02x.%02x.%02x.%02x.%02x.%02x\t",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
            fprintf(fichero3,"%x\n",htons(eth->h_proto));
        }else{
            printf("%02X.%02x.%02x.%02x.%02x.%02x\t",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
            printf("%02x.%02x.%02x.%02x.%02x.%02x\t",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
            printf("%x\n",htons(eth->h_proto));
        }
    }
    
    close(tuberia);
    pthread_exit(0);
}
