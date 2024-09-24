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