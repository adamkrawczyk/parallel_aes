#include "AES.h"

class AES_CBC : public AES
{
private:
  
public:
  AES_CBC(AESType aes_type);
  void AES_CBC_encript(state_type *in, state_type *out, w_type *w, int len, state_type *iv);
};
