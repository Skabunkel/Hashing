/*
*   My personal implementation of the MD5 hash algorithm in C99.
*   based on this psudocode https://en.wikipedia.org/wiki/MD5#Pseudocode
*
*   This implementation is for educational purposes and should be considered unsafe for password hashing.
*   I would like to make it safe, however i need to read more about what that means and how it is achived.
*
*   I have not tested it on a big endian machine so i hope it will work. don't know though. Now that i think about it probably not.
*/

#if !defined(_MD5_H)
#define _MD5_H

#if defined(__STDC__) && __STDC_VERSION__ >= 199901L
#include <stdbool.h>
#elif !defined(__cplusplus) && !defined(bool)
typedef enum { false, true } bool;
#endif // __STDC__

#include <memory.h>
#include <stdint.h>
#include <stdlib.h>

#if !defined(SECURE_ZERO)
#define SECURE_ZERO
// Based on some code in libsodium, their version is way more rigurus. So use libsodium of secure code.
void SecureZero(const uint8_t *buffer, const uint64_t length);
#endif  

#define MD5_HASH_DIGEST_SIZE 16

//I use a provided buffer here to make it thread safe, lets hope i dont destroy that somewhere else.
bool MD5(const uint8_t *message, const uint64_t length, 
         uint8_t *outputBuffer, const uint32_t outputLenght);

#endif