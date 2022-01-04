#include "AES_ECB.h"

AES_ECB::AES_ECB(AESType aes_type)
: AES(aes_type)
{
}

void AES_ECB::EncriptECB(state_type * in, state_type * out, w_type * w)
{
  AES::cipher(in, out, w);
}

unsigned char * AES_ECB::decryptECB(unsigned char in[], unsigned int inLen, unsigned char key[])
{
  unsigned char * out = new unsigned char[inLen];
  unsigned char * roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  keyExpansion(key, roundKeys);
  for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out + i, roundKeys);
  }

  delete[] roundKeys;

  return out;
}
