#include "AES_CBC.h"

void AES_CBC::AES_CBC_encript(state_type *in, state_type *out, w_type *w, int len, state_type *iv)
{

    for (int i = 0; i < len; i += 16)
    {
        for (int e = 0; e < 16; ++e)
        {
            in[i] ^= iv[e];
        }
        AES::Cipher(in, out, w); 

        iv = out;
        in += 16;
    }

}