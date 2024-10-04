// Devin Bidstrup
// Created : 10/04/24

#include "ecb.h"

int aes(const uint8_t key[AES_KEYLEN], uint8_t data[WSIZE][Nb], bool is_encrypt)
{
  // Generate round keys
  uint8_t round_keys[4*(Nr+1)][WSIZE];  
  if (keyExpansion(key, round_keys) == -1)
  {
    printf("Key Expansion Failed!!");
    return -1;
  }

  // Perform encrypt / decrypt
  if (is_encrypt)
  {
    if (cipher(data, round_keys) == -1)
    {
      printf("Cipher Failed!!");
      return -1;
    }
  }
  else
  {
    if(invCipher(data, round_keys) == -1)
    {
      printf("Inverse Cipher Failed!!");
    }
  }

  return 0;
}

