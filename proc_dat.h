#include <stdio.h>
#include "snoopy.h"
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>

void *procesar_datos(void *datos){
    struct parametros *param;
    int tuberia, long_dat;
    tuberia = open("/tmp/mi_fifo",O_RDONLY);

    long_dat=read(tuberia, &param, sizeof(struct parametros *));

    printf("hola soy el procesador de datos %d %s %d\n", long_dat, param->interfaz, param->n_paquetes);
    close(tuberia);
    pthread_exit(0);
}