#include "AES.h"

class AES_ECB : public AES
{
private:

public:
    AES_ECB(AESType aes_type);
    void AES_ECB_encript(state_type *in, state_type *out, w_type *w);
};
