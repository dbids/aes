// Devin Bidstrup
// Created : 9/23/24

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include "aes.h"

#define DEBUG_EN 1

void printWord(uint8_t word_in[WSIZE]);
void printKey(uint8_t* key_in);
void printState(uint8_t state_in[4][Nb]);
void printData(uint8_t* data, size_t data_size);

#endif // _DEBUG_H_
