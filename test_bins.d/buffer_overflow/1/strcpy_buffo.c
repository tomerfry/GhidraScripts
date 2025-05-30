#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buf[8];
    strcpy(buf, argv[1]);
    printf("Input argument is %s", buf);
    return 0;
}
