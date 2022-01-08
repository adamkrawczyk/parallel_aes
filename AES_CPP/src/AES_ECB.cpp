#include "AES_ECB.h"

AES_ECB::AES_ECB(AESType aes_type)
: AES(aes_type)
{
}

void AES_ECB::AES_ECB_encript(state_type *in, state_type *out, w_type *w)
{
    AES::Cipher(in, out, w);
}