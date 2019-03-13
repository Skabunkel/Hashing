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
#define BLAKE2B_CONSTANT_BLOCKBYTES 128
#define BLAKE2B_CONSTANT_HASH_VECTOR_SIZE  8

bool Is_Big_Endian()
{
    union 
    {
        uint32_t i;
        char c[4];
    } bint = { 0x01020304 };

    return bint.c[0] == 1;
}

void Flip_Uint64_Bytes(uint64_t *value)
{
    uint64_t standin = *value << 56;
    standin |= (*value & 0xff00) << 40;
    standin |= (*value & 0xff0000) << 24;
    standin |= (*value & 0xff000000) << 8;
    standin |= (*value & 0xff00000000) >> 8;
    standin |= (*value & 0xff0000000000) >> 24;
    standin |= (*value & 0xff000000000000) >> 40;
    standin |= (*value & 0xff00000000000000) >> 56;
    *value = standin;
}

static const uint8_t sigma[10][16] =
{
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
};

static const uint64_t Blake2BIV[BLAKE2B_CONSTANT_HASH_VECTOR_SIZE] =
{
  0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

typedef struct Blake2BState 
{
    uint64_t stateVector[BLAKE2B_CONSTANT_HASH_VECTOR_SIZE];
    uint8_t targetLength;
    uint8_t keyLength;
    uint64_t readblock;
    uint64_t totalBlocks;
    bool isBigEndian;
    uint8_t blocks[BLAKE2B_CONSTANT_BLOCKBYTES];
} Blake2BState;

uint64_t RightShift64(const uint64_t value, int bits)
{
    return ((value >> bits) | (value << (64 - bits)));
}

void Mix(uint64_t *va, uint64_t *vb, uint64_t *vc, uint64_t *vd, const uint64_t x, const uint64_t y)
{
    *va = *va + *vb + x;
    *vd = RightShift64(*vd ^ *va, 32);

    *vc = *vc + *vd;
    *vb = RightShift64(*vb ^ *vc, 24);

    *va = *va + *vb + y;
    *vd = RightShift64(*vd ^ *va, 16);

    *vc = *vc + *vd;
    *vb = RightShift64(*vb ^ *vc, 63);
}

void Blake2B_Compress(Blake2BState *state, const bool isLastBlock)
{
    uint64_t v[16];

    v[0] = state->stateVector[0];
    v[1] = state->stateVector[1];
    v[2] = state->stateVector[2];
    v[3] = state->stateVector[3];
    v[4] = state->stateVector[4];
    v[5] = state->stateVector[5];
    v[6] = state->stateVector[6];
    v[7] = state->stateVector[7];
    v[8] = Blake2BIV[0];
    v[9] = Blake2BIV[1];
    v[10] = Blake2BIV[2];
    v[11] = Blake2BIV[3];
    v[12] = Blake2BIV[4] ^ state->readblock;
    v[13] = Blake2BIV[5];
    v[14] = !isLastBlock ? Blake2BIV[6] : Blake2BIV[6] ^ 0xFFFFFFFFFFFFFFFF;
    v[15] = Blake2BIV[7];

    uint64_t *messageVector = (uint64_t*)state->blocks;

    if(state->isBigEndian)
    {
        Flip_Uint64_Bytes(&messageVector[0]);
        Flip_Uint64_Bytes(&messageVector[1]);
        Flip_Uint64_Bytes(&messageVector[2]);
        Flip_Uint64_Bytes(&messageVector[3]);
        Flip_Uint64_Bytes(&messageVector[4]);
        Flip_Uint64_Bytes(&messageVector[5]);
        Flip_Uint64_Bytes(&messageVector[6]);
        Flip_Uint64_Bytes(&messageVector[7]);
        Flip_Uint64_Bytes(&messageVector[8]);
        Flip_Uint64_Bytes(&messageVector[9]);
        Flip_Uint64_Bytes(&messageVector[10]);
        Flip_Uint64_Bytes(&messageVector[11]);
        Flip_Uint64_Bytes(&messageVector[12]);
        Flip_Uint64_Bytes(&messageVector[13]);
        Flip_Uint64_Bytes(&messageVector[14]);
        Flip_Uint64_Bytes(&messageVector[15]);
    }

    uint8_t st = 0;
    for (int i = 0; i < 12; i++)
    {
        st = (uint8_t)(i % 10);

        Mix(&v[0], &v[4], &v[8], &v[12], messageVector[sigma[st][0]], messageVector[sigma[st][1]]);
        Mix(&v[1], &v[5], &v[9], &v[13], messageVector[sigma[st][2]], messageVector[sigma[st][3]]);
        Mix(&v[2], &v[6], &v[10], &v[14], messageVector[sigma[st][4]], messageVector[sigma[st][5]]);
        Mix(&v[3], &v[7], &v[11], &v[15], messageVector[sigma[st][6]], messageVector[sigma[st][7]]);

        Mix(&v[0], &v[5], &v[10], &v[15], messageVector[sigma[st][8]], messageVector[sigma[st][9]]);
        Mix(&v[1], &v[6], &v[11], &v[12], messageVector[sigma[st][10]], messageVector[sigma[st][11]]);
        Mix(&v[2], &v[7], &v[8], &v[13], messageVector[sigma[st][12]], messageVector[sigma[st][13]]);
        Mix(&v[3], &v[4], &v[9], &v[14], messageVector[sigma[st][14]], messageVector[sigma[st][15]]);
    }

    state->stateVector[0] ^= v[0] ^ v[8];
    state->stateVector[1] ^= v[1] ^ v[9];
    state->stateVector[2] ^= v[2] ^ v[10];
    state->stateVector[3] ^= v[3] ^ v[11];
    state->stateVector[4] ^= v[4] ^ v[12];
    state->stateVector[5] ^= v[5] ^ v[13];
    state->stateVector[6] ^= v[6] ^ v[14];
    state->stateVector[7] ^= v[7] ^ v[15];
}

bool Blake2B_Init(Blake2BState *state, const uint8_t outLength, const uint8_t *key, const uint8_t keyLength, const uint8_t *salt, const uint8_t saltLength, const uint8_t *personalization, const uint8_t personalizationLength)
{
    state->isBigEndian = Is_Big_Endian();

    state->stateVector[1] = Blake2BIV[1];
    state->stateVector[2] = Blake2BIV[2];
    state->stateVector[3] = Blake2BIV[3];
    state->stateVector[4] = Blake2BIV[4];
    state->stateVector[5] = Blake2BIV[5];
    state->stateVector[6] = Blake2BIV[6];
    state->stateVector[7] = Blake2BIV[7];

    // Salt is 16 bytes at ofset 32.
    // Personalization is 16 bytes at ofset 48.
    uint8_t hashSt[BLAKE2B_CONSTANT_OUTANDKEYLENGTH] = { outLength, keyLength, 0x01, 0x01 };
    memset(hashSt + 4, 0, BLAKE2B_CONSTANT_OUTANDKEYLENGTH - 4);
    if (saltLength > 0)
    {
        memcpy(hashSt + 32, salt, saltLength);
    }

    if (personalizationLength > 0)
    {
        memcpy(hashSt + 48, personalization, personalizationLength);
    }

    // Cant test this yet but i think this would fix it on big endian machines.
//    if(state->isBigEndian) //when thinking about it this makes no sence, the buffer is 64 bytes and here i am flipping the first 8.
//    {
//        Flip_Uint64_Bytes((uint64_t*)&hashSt);
//    }

    uint8_t *IV0 = (uint8_t*)Blake2BIV;
    uint8_t *result = (uint8_t*)state->stateVector;
    #pragma GCC push_options
    #pragma GCC optimize("O0")
    for (int i = 0; i < BLAKE2B_CONSTANT_OUTANDKEYLENGTH; i++)
    {
        result[i] = IV0[i] ^ hashSt[i];
        hashSt[i] = '\0';
    }
    #pragma GCC pop_options

    state->targetLength = outLength;
    state->keyLength = keyLength;

    memset(state->blocks, 0, BLAKE2B_CONSTANT_BLOCKBYTES);

    if (keyLength > 0)
    {
        memcpy(state->blocks, key, keyLength);
        state->readblock += 128;
        Blake2B_Compress(state, state->totalBlocks == 0);
        memset(state->blocks, 0, keyLength);
    }

    return true;
}

void Blake2B_Hash(Blake2BState *state, const uint8_t *message, const uint64_t messageLength)
{
    uint64_t bytesLeft = messageLength;

    int readBytes = messageLength > BLAKE2B_CONSTANT_BLOCKBYTES ? BLAKE2B_CONSTANT_BLOCKBYTES : messageLength;
    memcpy(state->blocks, message, readBytes);

    uint64_t bytesRead = readBytes;
    state->readblock += readBytes;

    while (bytesLeft > BLAKE2B_CONSTANT_BLOCKBYTES)
    {
        Blake2B_Compress(state, false);
        bytesLeft -= readBytes;
        readBytes = bytesLeft > BLAKE2B_CONSTANT_BLOCKBYTES ? BLAKE2B_CONSTANT_BLOCKBYTES : bytesLeft;

        if (readBytes < BLAKE2B_CONSTANT_BLOCKBYTES)
        {
            memset(state->blocks, 0, BLAKE2B_CONSTANT_BLOCKBYTES);
        }

        memcpy(state->blocks, message + bytesRead, readBytes);

        bytesRead += readBytes;
        state->readblock += readBytes;
    }

    
}

void Blake2B_Finalize(Blake2BState *state, uint8_t *outBuffer, const uint64_t outLength)
{
    if(state->totalBlocks != 0 || state->keyLength == 0)
    {
        Blake2B_Compress(state, true);
    }

    #pragma GCC push_options
    #pragma GCC optimize("O0")
    memset(state->blocks, 0, BLAKE2B_CONSTANT_BLOCKBYTES);
    #pragma GCC pop_options
    
    if (state->isBigEndian)
    {
        Flip_Uint64_Bytes(&state->stateVector[0]);
        Flip_Uint64_Bytes(&state->stateVector[1]);
        Flip_Uint64_Bytes(&state->stateVector[2]);
        Flip_Uint64_Bytes(&state->stateVector[3]);
        Flip_Uint64_Bytes(&state->stateVector[4]);
        Flip_Uint64_Bytes(&state->stateVector[5]);
        Flip_Uint64_Bytes(&state->stateVector[6]);
        Flip_Uint64_Bytes(&state->stateVector[7]);
    }

    uint8_t *reader = (uint8_t*)&state->stateVector;

    memcpy(outBuffer, reader, outLength);
}

bool Blake2B(const uint8_t *message, const uint64_t messageLength, const uint8_t *key, const uint32_t keyLength, const uint8_t *salt, const uint32_t saltLength, const uint8_t *personalization, const uint32_t personalizationLength, uint8_t *outbuffer, const uint32_t outLength)
{
    if (message == NULL && messageLength > 0) return false;
    if (outbuffer == NULL || outLength == 0) return false;
    if (key == NULL && keyLength > 0) return false;

    if (outLength > BLAKE2B_CONSTANT_OUTANDKEYLENGTH) return false;
    if (keyLength > BLAKE2B_CONSTANT_OUTANDKEYLENGTH) return false;

    if (salt == NULL && saltLength > 0) return false;
    if (personalization == NULL && personalizationLength > 0) return false;

    if (saltLength > BLAKE2B_CONSTANT_SALT) return false;
    if (personalizationLength > BLAKE2B_CONSTANT_PERSONALIZATION) return false;

    Blake2BState cs;

    cs.readblock = 0;
    cs.totalBlocks = messageLength;

    if (!Blake2B_Init(&cs, (uint8_t)outLength, key, (uint8_t)keyLength, salt, (uint8_t)saltLength, personalization, (uint8_t)personalizationLength)) return false;

    Blake2B_Hash(&cs, message, messageLength);
    Blake2B_Finalize(&cs, outbuffer, outLength);
    return true;
}