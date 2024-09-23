// Devin Bidstrup
// Created : 9/22/24

#ifndef _AES_H_
#define _AES_H_

// --------- libraries --------- 
#include <stdint.h>
#include <stddef.h>

// --------- typedefs --------- 

// --------- defs --------- 
#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only
#define Nb 4            // Block length in 32 bit words
#define IV_LENGTH 96    // Only allow 96-bit IVs

#define AES128 1
//#define AES192 1
// #define AES256 1
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
int keyExpansion(const uint32_t* key, uint8_t* round_keys);
uint32_t rotWord (uint8_t* word_in);
uint32_t subWord (uint8_t* word_in);

// ------------------------------------------ Cipher ------------------------------------------
uint8_t subBytes(uint8_t byte_in);


// ------------------------------------------ Inverse Cipher ------------------------------------------ 
  


// ------------------------------------------ Common Functions ------------------------------------------
uint8_t sBox(uint8_t byte_in);

#endif // _AES_H_