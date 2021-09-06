#include <stdio.h>
#include "snoopy.h"
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include <linux/if_ether.h>

void guardar_trama(FILE *fichero,struct ethhdr *eth,int long_dat){
    /*imprime mac destino*/
    fprintf(fichero,"%02X.%02x.%02x.%02x.%02x.%02x\t",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
    /*imprime mac origen*/
    fprintf(fichero,"%02x.%02x.%02x.%02x.%02x.%02x\t",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
    /*imprime protocolo*/
    fprintf(fichero,"%x\t\t\t",htons(eth->h_proto));
    /*imprime longitud de la trama*/
    fprintf(fichero,"%d\t\t\t",long_dat);
    /*imprime carga util*/
    fprintf(fichero,"%d\n",(long_dat-sizeof(eth->h_dest)-sizeof(eth->h_dest)-sizeof(eth->h_proto)));
}

/*imprime las cabeceras de los logs*/
void guardar_cabezera(FILE *fichero){
    fprintf(fichero,"MAC destino\t\t\tMAC origen\t\t\tprotocolo\tlong trama\tcarga util\n");
}

/**/
struct n_mac *crear_nodo(struct ethhdr *eth){
    struct n_mac *nuevo= (struct n_mac *)malloc(sizeof(struct n_mac));
    nuevo->mac_origen[0]=eth->h_source[0];
    nuevo->mac_origen[1]=eth->h_source[1];
    nuevo->mac_origen[2]=eth->h_source[2];
    nuevo->mac_origen[3]=eth->h_source[3];
    nuevo->mac_origen[4]=eth->h_source[4];
    nuevo->mac_origen[5]=eth->h_source[5];
    nuevo->cont=1;
    nuevo->sig=NULL;
    return nuevo;
}

struct n_mac *agregar_lista(struct ethhdr *eth, struct n_mac *lista){
    struct n_mac *nuevo=crear_nodo(eth);
    if(lista==NULL){
        return nuevo;
    }else{
        nuevo->sig = lista;
        return nuevo;
    }
}

struct n_mac *contar_en_lista(struct ethhdr *eth, struct n_mac *lista){
    if(lista==NULL){
        lista=agregar_lista(eth,lista);
        return lista;
    }else{
        for(struct n_mac *actual= lista; actual!=NULL;actual=actual->sig){
            /*si la direccion mac de actual es igual a la de eth->h_sourse*/
            if(((eth->h_source[0]== actual->mac_origen[0] && eth->h_source[1]== actual->mac_origen[1]) && (eth->h_source[2]== actual->mac_origen[2] && eth->h_source[3]== actual->mac_origen[3])) && (eth->h_source[4]== actual->mac_origen[4] && eth->h_source[5]== actual->mac_origen[5])){
                actual->cont++;
                return lista;
            }else if(actual->sig==NULL){
                struct n_mac *nuevo=agregar_lista(eth,lista);
                return nuevo;
            }
        }
    }
}

void mostrar_lista(struct n_mac *lista){
    printf("Direccion origen\tpaquetes\n");
    for(struct n_mac *actual= lista; actual!=NULL;actual=actual->sig){
        printf("%x.%x.%x.%x.%x.%x\t",actual->mac_origen[0],actual->mac_origen[1],actual->mac_origen[2],actual->mac_origen[3],actual->mac_origen[4],actual->mac_origen[5]);
        printf("%d\n",actual->cont);
    }
}

/*funcion principal del procesador de datos*/
void *procesar_datos(void *datos){
    struct n_mac *lista=NULL;

    FILE *fichero,*fichero2,*fichero3,*fichero4,*fichero5;
    fichero=fopen("sniffer_IPv4.log","w");
    fichero2=fopen("sniffer_IPv6.log","w");
    fichero3=fopen("sniffer_ARP.log","w");
    fichero4=fopen("sniffer_descartados.log","w");

    /*descartados es la cnatidad de tramas IEEE, analizados Ethernet 2*/
    int IPv4=0, IPv6=0, ARP=0, descartados=0,analizados=0;

    struct parametros *param;
    /*long_dat es la trama leida de la tuberia, size_trama el tamaño de la trama en revfrom*/
    int tuberia, long_dat,size_trama;
    struct ethhdr *eth;
    char buffer[MAX_LINES];
    tuberia = open("/tmp/mi_fifo",O_RDONLY);

    long_dat=read(tuberia, &param, sizeof(struct parametros *));
    
    guardar_cabezera(fichero);
    guardar_cabezera(fichero2);
    guardar_cabezera(fichero3);
    guardar_cabezera(fichero4);

    for(int i = 0; i<param->n_paquetes;i++ ){
        /*primero leo la longitud de la trama*/
        long_dat=read(tuberia, &size_trama, sizeof(size_trama));

        /*leo la trama y convierto al tipo necesario*/
        long_dat=read(tuberia, &buffer, size_trama);
        eth = (struct ethhdr *)buffer;
        //IPv4
        if(htons(eth->h_proto) ==0x0800){
            IPv4++;
            analizados++;
            guardar_trama(fichero,eth,long_dat);
            lista=contar_en_lista(eth,lista);
        }//IPv6
        else if(htons(eth->h_proto) ==0x86DD){
            IPv6++;
            analizados++;
            guardar_trama(fichero2,eth,long_dat);
            lista=contar_en_lista(eth,lista);
        }//ARP
        else if(htons(eth->h_proto) ==0x0806){
            ARP++;
            analizados++;
            guardar_trama(fichero3,eth,long_dat);
            lista=contar_en_lista(eth,lista);
        }//descartados
        else{
            descartados++;
            guardar_trama(fichero4,eth,long_dat);
        }
    }
    /*cierre de ficheros no necesarios*/
    close(tuberia);
    close(fichero);
    close(fichero2);
    close(fichero3);
    close(fichero4);

    mostrar_lista(lista);
    /*escribo el fichero de resultados*/
    fichero5=fopen("sniffer_resultados.log","w");
    fprintf(fichero5,"\t\t\tResultados del analizis\n\n\n");
    fprintf(fichero5,"Total de paquetes: %d Total Ethernet II: %d Total IEEE 802.3: %d\t\n\n",param->n_paquetes, analizados,descartados);
    fprintf(fichero5,"Descripción de los paquetes analizados:\n");
    fprintf(fichero5,"Paquetes IPv4: %d\tPaquetes IPv6: %d\tPaquetes ARP: %d\n",IPv4,IPv6,ARP);

    close(fichero5);
    pthread_exit(0);
}