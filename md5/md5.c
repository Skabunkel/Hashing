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

#define HASH_VECTOR_SIZE 4
#define HASH_CHUNK_SIZE 64
#define K_VALUE_COUNT 64

#define MD5_HASH_DIGEST_SIZE 16

bool Is_Big_Endian()
{
    union 
    {
        uint32_t i;
        char c[4];
    } bint = { 0x01020304 };

    return bint.c[0] == 1;
}

void Flip_Uint32_Bytes(uint32_t *value)
{
    uint32_t standin = *value << 24;
    standin |= (*value & 0xff00) << 8;
    standin |= (*value & 0xff0000) >> 8;
    standin |= (*value & 0xff000000) >> 24;
    *value = standin;
}

uint32_t LeftShift32(const uint32_t value, int bits)
{
    return ((value << bits) | (value >> (32 - bits)));
}

void SecureZero(const uint8_t *buffer, const uint64_t length)
{
    volatile uint8_t *vBuffer = (volatile uint8_t*)buffer;
    uint64_t ofset = 0;

    while(ofset < length)
    {
        vBuffer[ofset] = 0;
        ofset++;
    }
}

const static uint8_t shiftVector[64] = 
{
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

const static uint32_t InitVector[HASH_VECTOR_SIZE] = 
{
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

const static uint32_t Kvalues[K_VALUE_COUNT] = 
{
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

typedef struct MD5State{
    bool is_big_endian;
    uint8_t chunk[HASH_CHUNK_SIZE];
    uint32_t hashVector[HASH_VECTOR_SIZE];
} MD5State;

void MD5_Init(MD5State *state)
{
    state->is_big_endian = Is_Big_Endian();
    memset(state->chunk, 0, HASH_CHUNK_SIZE);

    state->hashVector[0] = InitVector[0];
    state->hashVector[1] = InitVector[1];
    state->hashVector[2] = InitVector[2];
    state->hashVector[3] = InitVector[3];
}

void MD5_Hash(MD5State *state, const uint8_t *message, const uint64_t length)
{
    uint64_t byteOfset = 0;
    int32_t readBytes = HASH_CHUNK_SIZE > length ? length : HASH_CHUNK_SIZE;

    int32_t padd = readBytes % 64;
    uint64_t dataLeft = length;

    // TODO: move this to a sepret function.
    while(readBytes == HASH_CHUNK_SIZE)
    {
        memcpy(state->chunk, message+byteOfset, readBytes);
        MD5_Compress(state);
    
        byteOfset += readBytes;
        dataLeft -= readBytes;
        readBytes = dataLeft > HASH_CHUNK_SIZE ? HASH_CHUNK_SIZE : dataLeft;
    }
    
    memset(state->chunk, 0, HASH_CHUNK_SIZE);
    memcpy(state->chunk, message+byteOfset, readBytes);

    state->chunk[readBytes] = 0x80;

    if(readBytes >= 56)
    {
        MD5_Compress(state);
        memset(state->chunk, 0, HASH_CHUNK_SIZE);
    }

    uint64_t bits = (length)*8;
    memcpy(state->chunk+56, &bits, 8);
}

void MD5_Compress(MD5State *state)
{
    uint32_t *chunkReader = (uint32_t*)state->chunk;
    uint32_t workingSet[4];
    uint32_t F = 0,g = 0, tmp = 0;
    
    workingSet[0] = state->hashVector[0];
    workingSet[1] = state->hashVector[1];
    workingSet[2] = state->hashVector[2];
    workingSet[3] = state->hashVector[3];
    
    if(state->is_big_endian)
    {
        Flip_Uint32_Bytes(&chunkReader[0]);
        Flip_Uint32_Bytes(&chunkReader[1]);
        Flip_Uint32_Bytes(&chunkReader[2]);
        Flip_Uint32_Bytes(&chunkReader[3]);
        Flip_Uint32_Bytes(&chunkReader[4]);
        Flip_Uint32_Bytes(&chunkReader[5]);
        Flip_Uint32_Bytes(&chunkReader[6]);
        Flip_Uint32_Bytes(&chunkReader[7]);
        Flip_Uint32_Bytes(&chunkReader[8]);
        Flip_Uint32_Bytes(&chunkReader[9]);
        Flip_Uint32_Bytes(&chunkReader[10]);
        Flip_Uint32_Bytes(&chunkReader[11]);
        Flip_Uint32_Bytes(&chunkReader[12]);
        Flip_Uint32_Bytes(&chunkReader[13]);
        Flip_Uint32_Bytes(&chunkReader[14]);
        Flip_Uint32_Bytes(&chunkReader[15]);
    }

    for(int i = 0; i < HASH_CHUNK_SIZE; i++)
    {
        if(i < MD5_HASH_DIGEST_SIZE)
        {
            F = ((workingSet[1] & workingSet[2]) | ((~workingSet[1]) & workingSet[3]));
            g = i;
        }
        else if(i < 32)
        {
            F = ((workingSet[3] & workingSet[1]) | ((~workingSet[3]) & workingSet[2]));
            g = (5 * i + 1)%MD5_HASH_DIGEST_SIZE;
        }
        else if(i < 48)
        {
            F = (workingSet[1] ^ workingSet[2] ^ workingSet[3]);
            g = (3 * i + 5)%MD5_HASH_DIGEST_SIZE;
        }
        else
        {
            F = (workingSet[2] ^ (workingSet[1] | (~workingSet[3])));
            g = (7 * i)%MD5_HASH_DIGEST_SIZE;
        }
        uint32_t tmps = (workingSet[0] + F + Kvalues[i] + chunkReader[g]);
        tmp = workingSet[3];

        workingSet[3] = workingSet[2];
        workingSet[2] = workingSet[1];
        workingSet[1] = workingSet[1] + LeftShift32(tmps, shiftVector[i]);
        workingSet[0] = tmp;
    }

    state->hashVector[0] += workingSet[0];
    state->hashVector[1] += workingSet[1];
    state->hashVector[2] += workingSet[2];
    state->hashVector[3] += workingSet[3];
}

void MD5_Finalize(MD5State *state, uint8_t *outputBuffer, const uint64_t outputLenght)
{
    MD5_Compress(state);

    SecureZero(state->chunk, HASH_CHUNK_SIZE);

    if(state->is_big_endian)
    {
       Flip_Uint32_Bytes(&state->hashVector[0]);
       Flip_Uint32_Bytes(&state->hashVector[1]);
       Flip_Uint32_Bytes(&state->hashVector[2]);
       Flip_Uint32_Bytes(&state->hashVector[3]);
    }

    uint8_t *reader = (uint8_t*)state->hashVector;
    memcpy(outputBuffer, reader, MD5_HASH_DIGEST_SIZE);
}

bool MD5(const uint8_t *message, const uint64_t length, uint8_t *outputBuffer, const uint32_t outputLenght)
{
    if(outputLenght < MD5_HASH_DIGEST_SIZE) return false;
    MD5State state;

    MD5_Init(&state);
    MD5_Hash(&state, message,length);
    MD5_Finalize(&state, outputBuffer, outputLenght);

    return true;
}