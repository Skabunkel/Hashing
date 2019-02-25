/*  
*   My personal implementation of the blake2B hash algorithm in C99.
*   based on this psudocode https://en.wikipedia.org/wiki/BLAKE_%28hash_function%29#BLAKE2
*   and refrences from https://github.com/BLAKE2/BLAKE2/
*   
*   This implementation is not a full implimentation since it can only access 2^64 bytes instead of the full 2^128 bytes the psudocode refrences
*   For a safe and tested implementation see https://github.com/BLAKE2/BLAKE2/
*   
*   This implementation is for educational purposes and should be considered unsafe for password hashing.
*   I would like to make it safe, however i need to read more about what that means and how it is achived.
*   
*   I have not tested it on a big endian machine so i hope it will work. don't know though. Now that i think about it probably not.
*/  


#include "blake2b.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argv, char **argc)
{
    if(argv <= 3)
    {
        printf("inputs should be key\n");
        printf("%s targetLength message messageLength\n", argc[0]);
        printf("%s targetLength message messageLength key keyLength\n", argc[0]);
        return -1;
    }

    int targetLength = atoi(argc[1]);

    char *msg = argc[2];
    int msglen = atoi(argc[3]);

    char *key = NULL;
    int keylen = 0;

    if(argv >= 6)
    {
        key = argc[4];
        keylen = atoi(argc[5]);
    }

    printf("Is big endian: %s\n", Is_Big_Endian() ? "true" : "false");

    uint8_t buffer[targetLength];
    memset(buffer, 0, targetLength);
    bool success = Blake2B((const uint8_t*)msg, msglen, (const uint8_t*)key, keylen, NULL, 0, NULL, 0, buffer, targetLength);

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