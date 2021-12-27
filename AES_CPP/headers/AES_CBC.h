#include "AES.h"

class AES_CBC : public AES
{
private:
  
public:
  void AES_CBC_encript(state_type *in, state_type *out, w_type *w, int len, state_type *iv);
  void KeyExpansion(w_type *key, w_type *w);
};
