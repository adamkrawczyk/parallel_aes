#include "AES_ECB.h"

void AES_ECB::AES_ECB_encript(state_type *in, state_type *out, w_type *w)
{
    AES::Cipher(in, out, w);
}