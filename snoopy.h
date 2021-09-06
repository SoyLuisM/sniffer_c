#ifndef _SNOOPY
#define _SNOOPY
struct parametros{
    char *interfaz;
    int n_paquetes;
};
/*el tamaño maximo de la trama ethernet es 1518 bytes
dejo este valor nomas por que si*/
#define MAX_LINES 65536 

struct n_mac{
    char mac_origen[6];
    int cont;
    struct n_mac *sig;
};
//#include  ″snoopy.c″
#endif