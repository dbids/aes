// Devin Bidstrup
// Created : 9/22/24

#ifndef _AES_H_
#define _AES_H_

// --------- libraries --------- 
#include <stdint.h>
#include <stddef.h>

// --------- defs --------- 
#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only
#define Nb 4            // Block length in 32 bit words
#define IV_LENGTH 96    // Only allow 96-bit IVs
#define WSIZE 4         // Size of a word in bytes

#define AES128 1
//#define AES192 1
//#define AES256 1
#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
    #define Nk 6
    #define Nr 12
#else
    #define AES_KEYLEN 16      // Key length in bytes
    #define AES_keyExpSize 176
    #define Nk 4               // The number of 32 bit words in a key.
    #define Nr 10              // The number of rounds in AES Cipher.
#endif

// --------- typedefs ---------

// --------- Functions --------- 

// ------------------------------------------ AES Top ------------------------------------------ 
// AES Base Function
int aes (
  const uint8_t* key,     /*input data to be encrypted/decrypted*/
  const uint8_t* iv,      /*nonce or initialization vector, 12B/96b only*/
  uint8_t*       data,    /*input data to be encrypted/decrypted*/
  size_t         data_len /*must be a multiple of AES_BLOCKLEN (16B/128b)*/
);

// ------------------------------------------ Key Expansion ------------------------------------------
int keyExpansion(const uint8_t key[AES_KEYLEN], uint8_t w[4*(Nr+1)][WSIZE]);
void rotWord (uint8_t word_in[WSIZE]);
void subWord (uint8_t word_in[WSIZE]);

// ------------------------------------------ Cipher ------------------------------------------
int cipher(uint8_t state[4][Nb], uint8_t w[4*(Nr+1)][WSIZE]);
void subBytes(uint8_t state[4][Nb]);
void shiftRows(uint8_t state[4][Nb]); 
void mixColumns(uint8_t state[4][Nb]); 
void addRoundKey(uint8_t state[4][Nb], uint8_t fourW[4][WSIZE]); 


// ------------------------------------------ Inverse Cipher ------------------------------------------ 
  


// ------------------------------------------ Common Functions ------------------------------------------
uint8_t sBox(uint8_t byte_in);

uint8_t gfAdd(uint8_t a, uint8_t b);
uint8_t xTimes(uint8_t b);
uint8_t gfMult(uint8_t b, uint8_t c);
// void gfFixedMatrixMult(uint8_t a[4][4], uint8_t b[4], uint8_t d[4]); UNUSED

#endif // _AES_H_
