#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void dangerZONE(){
    
    printf("sucess\n");

    char *name[] = {"/bin/bash", NULL};
    setuid(0);
    execvp(name[0], name);

}

void vuln(char* string){

    char buffer[20] = {0};
    strcpy(buffer, string);
    printf(buffer);
}

int main(int argc, char *argv[]){

    printf("Hello \n");

    if(argc > 1){

        vuln(argv[1]);
        
    }else{
        printf("Enter data...\n");
    }

    
    return 0;
}