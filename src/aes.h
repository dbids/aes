// Devin Bidstrup
// Created : 9/22/24

#ifndef _AES_H_
#define _AES_H_

// --------- libraries ---------
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

// --------- defs ---------
#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only
#define Nb 4            // Block length in 32 bit words
#define IV_LENGTH 96    // Only allow 96-bit IVs
#define WSIZE 4         // Size of a word in bytes

//#define AES128 1
//#define AES192 1
#define AES256 1
#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
    #define Nr 12
#else
    #define AES_KEYLEN 16      // Key length in bytes
    #define AES_keyExpSize 176
    #define Nr 10              // The number of rounds in AES Cipher.
#endif

#define Nk AES_KEYLEN/WSIZE // The number of 32 bit words in a key.

// --------- typedefs ---------
// Block size words
typedef uint8_t block_t[WSIZE][Nb];

// --------- Functions ---------

// ------------------------------------------ AES Top ------------------------------------------
int aes(const uint8_t key[AES_KEYLEN], block_t data, const bool is_encrypt);

// ------------------------------------------ Key Expansion ------------------------------------------
int keyExpansion(const uint8_t key[AES_KEYLEN], uint8_t w[4*(Nr+1)][WSIZE]);
void rotWord (uint8_t word_in[WSIZE]);
void subWord (uint8_t word_in[WSIZE]);

// ------------------------------------------ Cipher ------------------------------------------
int  cipher     (block_t state, uint8_t w[4*(Nr+1)][WSIZE]);
void subBytes   (block_t state);
void shiftRows  (block_t state);
void mixColumns (block_t state);
void addRoundKey(block_t state, uint8_t fourW[4][WSIZE]);


// ------------------------------------------ Inverse Cipher ------------------------------------------
int  invCipher    (block_t state, uint8_t w[4*(Nr+1)][WSIZE]);
void invSubBytes  (block_t state);
void invShiftRows (block_t state);
void invMixColumns(block_t state);


// ------------------------------------------ Common Functions ------------------------------------------
uint8_t sBox   (uint8_t byte_in);
uint8_t invSBox(uint8_t byte_in);

uint8_t gfAdd (uint8_t a, uint8_t b);
uint8_t xTimes(uint8_t b);
uint8_t gfMult(uint8_t b, uint8_t c);
// void gfFixedMatrixMult(uint8_t a[4][4], uint8_t b[4], uint8_t d[4]); UNUSED

#endif // _AES_H_
