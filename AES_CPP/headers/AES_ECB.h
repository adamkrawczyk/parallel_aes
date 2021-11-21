#include "AES.h"

class AES_ECB : public AES
{
private:

public:

    void AES_ECB_encript(state_type *in, state_type *out, w_type *w);
};
