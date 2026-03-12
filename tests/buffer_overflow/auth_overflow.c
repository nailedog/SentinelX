#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHANNEL 24

void admin() {

}

int check_authentication(char *password) {
    
    int flag = 0;

    char buffer[14];

    strcpy(buffer, password);

    if (strcmp(buffer, "brilling") == 0) {
        flag = 1;
    }

    return flag;
}

int main(int argc, char *argv[]) {
    if (check_authentication(argv[1])) {
        
    }
    return 0;
}
