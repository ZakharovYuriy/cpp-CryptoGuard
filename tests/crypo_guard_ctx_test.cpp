#include <gtest/gtest.h>
#include <ostream>

#include "crypto_guard_ctx.h"

TEST(TestComponentName, TestEncriptDecrypt) 
{ 
    using namespace CryptoGuard;
    CryptoGuardCtx cryptoGuard;

    std::string data = "Hello, world!";
    std::string password = "123321";
    std::istringstream inStreamData(data);
    std::ostringstream outStream;

    cryptoGuard.EncryptFile(inStreamData, outStream, password);

    std::string encryptedResult = outStream.str(); 
    EXPECT_FALSE(encryptedResult.empty());

    outStream.str("");
    outStream.clear();

    std::istringstream inStreamEncrypted(encryptedResult);
    cryptoGuard.DecryptFile(inStreamEncrypted, outStream, password);
    std::string decryptedResult = outStream.str(); 
    EXPECT_FALSE(decryptedResult.empty());
    EXPECT_EQ(data, decryptedResult);
}
