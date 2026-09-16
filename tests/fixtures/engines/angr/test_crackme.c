#include <stdio.h>
#include <string.h>

int check_key(char *input) {
    if (input[0] == 'P' && input[1] == 'A' && input[2] == 'S' && input[3] == 'S') {
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: crackme <key>\n");
        return 1;
    }
    if (check_key(argv[1])) {
        printf("SUCCESS: Password Accepted!\n");
        return 0;
    } else {
        printf("FAILURE: Access Denied.\n");
        return 1;
    }
}
