// Devin Bidstrup
// Created : 9/22/24

#ifndef _AES_H_
#define _AES_H_

// --------- libraries --------- 
#include <stdint.h>
#include <stddef.h>

// --------- typedefs --------- 
#define uint128_t __int128

// --------- defs --------- 
#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only
#define IV_LENGTH 96 // Only allow 96-bit IVs

// --------- Functions --------- 

// AES Base Function
int aes (
  const uint8_t* key,     /*input data to be encrypted/decrypted*/
  size_t         key_len, /*key length must be 16B, 24B, or 32B*/
  const uint8_t* iv,      /*nonce or initialization vector, 12B/96b only*/
  uint8_t*       data,    /*input data to be encrypted/decrypted*/
  size_t         data_len /*must be a multiple of AES_BLOCKLEN (16B/128b)*/
);

#endif // _AES_H_