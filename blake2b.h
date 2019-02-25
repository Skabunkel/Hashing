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

#if !defined(_BLAKE2B_H)
#define _BLAKE2B_H

#define BLAKE2B_CONSTANT_OUTANDKEYLENGTH 64
#define BLAKE2B_CONSTANT_PERSONALIZATION 16
#define BLAKE2B_CONSTANT_SALT 16

#if defined(__STDC__) && __STDC_VERSION__ >= 199901L
    #include <stdbool.h>
#elif !defined(__cplusplus) && !defined(bool)
    typedef enum { false, true } bool;
#endif // __STDC__

#include <stdint.h>
#include <memory.h>

// message the bytes to hash.
// messageLength the number of bytes to hash.
// key the key to hash with.
// keyLength the length of the key max length 64.
// salt the hash salt max 16 bytes.
// saltLength the length of the salt field max value 16.
// personalization the hash personalization max 16 bytes.
// personalizationLength the length of the personalization field max value 16.
// outbuffer output buffer.
// outLength the length of the output buffer max value 64.

// This implementation can only encode 18446744073709551616 bytes or 16EiB.
bool Blake2B(const uint8_t *message, const uint64_t messageLength, const uint8_t *key, const uint32_t keyLength, const uint8_t *salt, const uint32_t saltLength, const uint8_t *personalization, const uint32_t personalizationLength,  uint8_t *outbuffer, const uint32_t outLength);
//const char *HexStr(uint8_t *byteBuffer, const uint32_t length);
bool Is_Big_Endian();
#endif // _BLAKE2B_H