#include <stdio.h>

void *procesar_datos(void *datos){
    int tuberia, long_dat;

    printf("hola soy el procesador de datos\n");
    pthread_exit(0);
}