#include "AES.h"

class AES_ECB : public AES
{
private:
public:
  AES_ECB(int Nk_tmp, int Nr_tmp, int Nb_tmp);
  void AES_ECB_encript(state_type * in, state_type * out, w_type * w);
};
