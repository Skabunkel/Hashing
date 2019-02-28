/*
*   My personal implementation of the MD5 hash algorithm in C99.
*   based on this psudocode https://en.wikipedia.org/wiki/MD5#Pseudocode
*
*   This implementation is for educational purposes and should be considered unsafe for password hashing.
*   I would like to make it safe, however i need to read more about what that means and how it is achived.
*
*   I have not tested it on a big endian machine so i hope it will work. don't know though. Now that i think about it probably not.
*/

#include "md5.h"
#include <stdio.h>

int main(int argv, char **argc)
{
    if(argv <= 2)
    {
        printf("inputs should be key\n");
        printf("%s message messageLength\n", argc[0]);
        return -1;
    }

    int targetLength = 16;

    char *msg = argc[1];
    int msglen = abs(atoi(argc[2]));

    uint8_t buffer[targetLength];
    memset(buffer, 0, targetLength);
    bool success = MD5((const uint8_t*)msg, msglen, buffer, targetLength);

    if(success)
    {
        for(int i = 0; i < targetLength; i++)
        {
            printf("%02x", buffer[i]);
        }
        printf("\n");
    }
    else
    {
        printf("Failed\n");
        return -1;
    }

    return 0;
}