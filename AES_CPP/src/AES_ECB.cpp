#include "AES_ECB.h"

// AES_ECB::AES_ECB(const int Nk_tmp, const int Nr_tmp, const int Nb_tmp){}

void AES_ECB::AES_ECB_encript(state_type * in, state_type * out, w_type * w)
{
  AES::Cipher(in, out, w);
}
