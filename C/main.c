// Devin Bidstrup
// Created : 9/22/24

#include <stdio.h>
#include <aes.h>

int main(int argc, char *argv[]) {

  // Define sample test case variables
  uint8_t key[16];
  size_t  key_len = 16;
  uint8_t iv[12];
  uint8_t data[16];
  size_t  data_len = 16;
  for (int key_idx = 0; key_idx < 16; key_idx++)
    key[key_idx] = 0;
  for (int iv_idx = 0; iv_idx < 12; iv_idx++)
    iv[iv_idx] = 0;
  for (int data_idx = 0; data_idx < 16; data_idx++)
    data[data_idx] = 0;

  // Call AES function
  int rc;
  rc = aes(key, key_len, iv, data, data_len);
  printf("%d\n\n", rc);


  // TEMP TEST
  printf("%x\n\n", SBox(0x53));
}