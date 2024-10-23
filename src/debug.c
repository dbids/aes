// Devin Bidstrup
// Created : 9/23/24

#include <stdio.h>
#include "aes.h"

void printWord(uint8_t word_in[WSIZE])
{
  for (int b_idx = 0; b_idx < WSIZE; b_idx++)
  {
    printf("%02x", word_in[b_idx]);
  }
}

void printKey(uint8_t* key_in)
{
  for (int n_idx = 0; n_idx < Nk; n_idx++)
  {
    for (int b_idx = 0; b_idx < WSIZE; b_idx++)
    {
      printf("%02x", key_in[WSIZE*n_idx + b_idx]);
    }
  }
}

void printState(uint8_t state_in[4][Nb])
{
  for (int row = 0; row < 4; row++)
  {
    for (int col = 0; col < Nb; col++)
    {
      printf("%02x ", state_in[row][col]);
    }
    printf("\n");
  }
}

void printData(uint8_t* data, size_t data_size)
{
  for (int d = 0; d < data_size; d++)
  {
    printf("%02x", data[d]);
  }
  printf("\n");
}
