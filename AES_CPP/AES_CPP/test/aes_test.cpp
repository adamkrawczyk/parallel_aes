#include <gtest/gtest.h>
#include "AES_CBC.h"
#include "AES_ECB.h"

struct ProjectTests : public ::testing::Test
{
  virtual void SetUp() override
  {
    printf("setup!!!!!!!!!\n");
  }
  virtual void TearDown()
  {
    printf("closing!!!!!!!\n");
  }
};

TEST_F(ProjectTests, DummyTest)
{
  EXPECT_EQ(true, true);
}

TEST_F(ProjectTests, AesEcbTest)
{
  // aes256

  const int Nk = 8;
  const int Nr = 14; // liczba rund szyfrowania
  const int Nb = 4;

  AES_ECB aes_ecb(Nk, Nr, Nb);
  EXPECT_EQ(true, true);
}
