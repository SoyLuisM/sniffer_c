#include <stdlib.h>
#include "sniffer.h"
#include "proc_dat.h"

int main(int argc, char *argv[]){

    if(argc == 3){
        struct parametros param;
        pthread_t id_sniffer;
        pthread_t id_proc_dat;

        param.interfaz=argv[1];
        param.n_paquetes=atoi(argv[2]);
        
        pthread_create(&id_sniffer, NULL, sniffer, (void *)&param);
        pthread_create(&id_proc_dat, NULL, procesar_datos, NULL);

        pthread_join(id_sniffer,NULL);
        pthread_join(id_proc_dat,NULL);
        
    }else{
        printf("Error en los parametros sintaxis\n");
        printf("sudo ./main Interfaz Num_paquetes\n");
    }
    return 1;
}