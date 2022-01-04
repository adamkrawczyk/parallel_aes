#include "AES.h"

class AES_CBC : public AES
{
private:
  void keyExpansion(w_type * key, w_type * w);
  void subBytes(state_type ** state);
  void cipher(state_type * in, state_type * out, w_type * w);

public:
  void AesCbcEncript(state_type * in, state_type * out, w_type * w, int len, state_type * iv);
};
