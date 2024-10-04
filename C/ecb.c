// Devin Bidstrup
// Created : 10/04/24

#include "ecb.h"

int aes_ecb(const uint8_t key[AES_KEYLEN], uint8_t* data, const bool is_encrypt, size_t data_size)
{
  // Check for block size data input
  if (data_size % AES_BLOCKLEN)
  {
    printf("Input can only be in block (16B/128b) size!!");
    return -1;
  }

  // Call AES for each block
  size_t block_num = data_size / AES_BLOCKLEN;
  block_t block;
  for (int b_idx = 0; b_idx < block_num; b_idx++)
  {
    for (int i = 0; i < Nb; i++)
    {
      for (int j = 0; j < WSIZE; j++)
      {
        block[i][j] = data[(b_idx * AES_BLOCKLEN) + (i * Nb) + j];
      }
    }
    if (aes(key, block, is_encrypt))
    {
      printf("AES function failed");
      return -1;
    }
  }

  return 0;
}

