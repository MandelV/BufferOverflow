#include <stdio.h>
#include <stdlib.h>
#include <string.h>



void vuln(char* string){

    char buffer[512] = {0};
    strcpy(buffer, string);
}

int main(int argc, char *argv[]){

    printf("Hello \n");

    if(argc > 1)
        vuln(argv[1]);    
    
    return 0;
}