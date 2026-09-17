#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void copy_it(char *input) {
    char buf[64];
    strcpy(buf, input);   /* stack buffer overflow */
    printf("%s\n", buf);
}
void run_cmd(char *arg) {
    system(arg);          /* command injection */
}
int main(int argc, char **argv) {
    if (argc > 1) copy_it(argv[1]);
    return 0;
}