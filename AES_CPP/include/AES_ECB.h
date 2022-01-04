#include "AES.h"

class AES_ECB : public AES
{
private:
public:
  AES_ECB(AESType aes_type);
  void EncriptECB(state_type * in, state_type * out, w_type * w);
  unsigned char * decryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[]);
};
