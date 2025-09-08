#include <gtest/gtest.h>

#include "crypto_guard_ctx.h"

namespace {
const std::string data = "Hello, world!";
const std::string password = "123321";
const std::string differentData = "Hello!";
}  // namespace

TEST(TestComponentName, TestEncriptDecrypt) {
    using namespace CryptoGuard;
    CryptoGuardCtx cryptoGuard;

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

TEST(TestComponentName, TestChecksum) {
    using namespace CryptoGuard;
    CryptoGuardCtx cryptoGuard;

    std::istringstream inStreamData(data);
    std::istringstream inStreamDifferentData(differentData);

    const std::string dataChecksum = cryptoGuard.CalculateChecksum(inStreamData);
    const std::string differentDataChecksum = cryptoGuard.CalculateChecksum(inStreamDifferentData);

    EXPECT_NE(data, differentDataChecksum);

    std::istringstream inStreamDataSecond(data);
    const std::string dataChecksumSecondRun = cryptoGuard.CalculateChecksum(inStreamDataSecond);
    EXPECT_EQ(dataChecksum, dataChecksumSecondRun);
}

TEST(TestComponentName, CombineTest) {
    using namespace CryptoGuard;
    CryptoGuardCtx cryptoGuard;

    std::istringstream inStreamData(data);
    std::ostringstream outStream;

    const std::string originalDataChecksum = cryptoGuard.CalculateChecksum(inStreamData);

    // reset Positon
    inStreamData.clear();
    inStreamData.seekg(0);

    cryptoGuard.EncryptFile(inStreamData, outStream, password);
    std::string encryptedData = outStream.str();

    std::istringstream encryptedDataInStream(encryptedData);
    const std::string encryptedDataChecksum = cryptoGuard.CalculateChecksum(encryptedDataInStream);
    EXPECT_NE(originalDataChecksum, encryptedDataChecksum);

    outStream.str("");
    outStream.clear();
    encryptedDataInStream.clear();
    encryptedDataInStream.seekg(0);

    cryptoGuard.DecryptFile(encryptedDataInStream, outStream, password);
    std::string decryptedData = outStream.str();

    std::istringstream decryptedDataInStream(decryptedData);
    const std::string decryptedDataChecksum = cryptoGuard.CalculateChecksum(decryptedDataInStream);
    EXPECT_EQ(originalDataChecksum, decryptedDataChecksum);
}

// Custom streambuf that always fails on write (overflow returns EOF).
class FailingBuf : public std::stringbuf {
    int overflow(int) override { return traits_type::eof(); }
};

TEST(TestComponentName, ThrowOnBrokenIO) {
    using namespace CryptoGuard;
    {
        std::istringstream badIn(data);
        badIn.setstate(std::ios::badbit);
        std::ostringstream goodOut;

        CryptoGuardCtx ctx;
        EXPECT_THROW(ctx.CalculateChecksum(badIn), std::runtime_error);
        EXPECT_THROW(ctx.EncryptFile(badIn, goodOut, password), std::runtime_error);
        EXPECT_THROW(ctx.DecryptFile(badIn, goodOut, password), std::runtime_error);
    }

    {
        std::istringstream goodIn1(data);

        FailingBuf buf;
        std::ostream badOut(&buf);

        CryptoGuardCtx ctx;
        EXPECT_THROW(ctx.EncryptFile(goodIn1, badOut, password), std::runtime_error);

        std::istringstream goodIn2(data);
        EXPECT_THROW(ctx.DecryptFile(goodIn2, badOut, password), std::runtime_error);
    }

    {
        std::istringstream badIn(data);
        badIn.setstate(std::ios::badbit);

        std::ostringstream badOut;
        badOut.setstate(std::ios::badbit);

        CryptoGuardCtx ctx;
        EXPECT_THROW(ctx.EncryptFile(badIn, badOut, password), std::runtime_error);
        EXPECT_THROW(ctx.DecryptFile(badIn, badOut, password), std::runtime_error);
    }
}