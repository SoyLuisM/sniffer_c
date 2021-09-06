#include <stdio.h>
#include "snoopy.h"
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include <linux/if_ether.h>

void guardar_trama(FILE *fichero,struct ethhdr *eth,int long_dat){
    fprintf(fichero,"%02X.%02x.%02x.%02x.%02x.%02x\t",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
    fprintf(fichero,"%02x.%02x.%02x.%02x.%02x.%02x\t",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
    fprintf(fichero,"%x\t\t\t",htons(eth->h_proto));
    fprintf(fichero,"%d\t\t",long_dat);
    fprintf(fichero,"%d\n",(long_dat-(sizeof(&eth->h_dest)*6)-(sizeof(&eth->h_source)*6)-sizeof(&eth->h_proto)));
}
void guardar_cabezera(FILE *fichero){
    fprintf(fichero,"MAC destino\t\t\tMAC origen\t\t\tprotocolo\tlong trama\tcarga util\n");
}
void *procesar_datos(void *datos){
    FILE *fichero,*fichero2,*fichero3,*fichero4,*fichero5;
    fichero=fopen("sniffer_IPv4.log","w");
    fichero2=fopen("sniffer_IPv6.log","w");
    fichero3=fopen("sniffer_ARP.log","w");
    fichero4=fopen("sniffer_descartados.log","w");

    int IPv4=0, IPv6=0, ARP=0, descartados=0,analizados=0;

    struct parametros *param;
    int tuberia, long_dat;
    struct ethhdr *eth;
    char buffer[MAX_LINES];
    tuberia = open("/tmp/mi_fifo",O_RDONLY);

    long_dat=read(tuberia, &param, sizeof(struct parametros *));
    
    guardar_cabezera(fichero);
    guardar_cabezera(fichero2);
    guardar_cabezera(fichero3);
    guardar_cabezera(fichero4);

    for(int i = 0; i<param->n_paquetes;i++ ){
        long_dat=read(tuberia, buffer, MAX_LINES);
        eth = (struct ethhdr *)buffer;
        //IPv4
        if(htons(eth->h_proto) ==0x0800){
            IPv4++;
            analizados++;
            guardar_trama(fichero,eth,long_dat);
        }//IPv6
        else if(htons(eth->h_proto) ==0x86DD){
            IPv6++;
            analizados++;
            guardar_trama(fichero2,eth,long_dat);
        }//ARP
        else if(htons(eth->h_proto) ==0x0806){
            ARP++;
            analizados++;
            guardar_trama(fichero3,eth,long_dat);
        }//descartados
        else{
            descartados++;
            guardar_trama(fichero4,eth,long_dat);
        }
    }

    close(tuberia);
    close(fichero);
    close(fichero2);
    close(fichero3);
    close(fichero4);

    fichero5=fopen("sniffer_resultados.log","w");
    fprintf(fichero5,"\t\t\tResultados del analizis\n\n\n");
    fprintf(fichero5,"Total de paquetes: %d Total Ethernet II: %d Total IEEE 802.3: %d\t\n\n",param->n_paquetes, analizados,descartados);
    fprintf(fichero5,"Descripción de los paquetes analizados:\n");
    fprintf(fichero5,"Paquetes IPv4: %d\tPaquetes IPv6: %d\tPaquetes ARP: %d\n",IPv4,IPv6,ARP);

    close(fichero5);
    pthread_exit(0);
}