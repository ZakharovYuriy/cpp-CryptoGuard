#include "crypto_guard_ctx.h"

#include <array>
#include <iomanip>
#include <iostream>
#include <sstream> 
#include <vector>

#include <openssl/evp.h>

namespace CryptoGuard {

struct AesCipherParams {
    enum class CryptoOperaTionType{
        DECRYPT = 0,
        ENCRYPT = 1
    };

    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    CryptoOperaTionType encrypt;
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::PImpl {
public:
    PImpl();
    PImpl(const PImpl &rhd)=delete;
    PImpl &operator=(const PImpl &rhd)=delete;
    PImpl(PImpl &&rhd)=default;
    PImpl &operator=(PImpl &&rhd)=default;
    ~PImpl()=default;

    void EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password);
    void DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password);
    [[nodiscard]] std::string CalculateChecksum(std::istream &inStream);

private:
AesCipherParams CreateChiperParamsFromPassword(std::string_view password);
void ApplyCryptoOperation(std::istream &inStream, std::ostream &outStream, const AesCipherParams& params);

private:
std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); })> chiper_ctx_;
std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ptr) { EVP_MD_CTX_free(ptr); })> md_ctx_;
};

CryptoGuardCtx::PImpl::PImpl():
    chiper_ctx_(EVP_CIPHER_CTX_new()),
    md_ctx_(EVP_MD_CTX_new())
{
    if (!chiper_ctx_) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    if (!md_ctx_) throw std::runtime_error("Failed to create EVP_MD_CTX");
};

void CryptoGuardCtx::PImpl::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) 
{
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = AesCipherParams::CryptoOperaTionType::ENCRYPT;
    ApplyCryptoOperation(inStream,outStream,params);
}

void CryptoGuardCtx::PImpl::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) 
{
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = AesCipherParams::CryptoOperaTionType::DECRYPT;
    ApplyCryptoOperation(inStream,outStream,params);
}

std::string CryptoGuardCtx::PImpl::CalculateChecksum(std::istream &inStream) 
{
    if (!EVP_DigestInit_ex(md_ctx_.get(), EVP_sha256(), nullptr)) throw std::runtime_error("EVP_DigestInit_ex failed");

    const std::size_t BUF_SIZE = 4096;
    std::vector<unsigned char> inBuf(BUF_SIZE);

    if (inStream.bad()) throw std::runtime_error("Stream read error (badbit set)");
    while (inStream) {
        inStream.read(reinterpret_cast<char*>(inBuf.data()), BUF_SIZE);
        std::streamsize bytesRead = inStream.gcount();
        if (inStream.bad()) throw std::runtime_error("Stream read error (badbit set)");

        if (bytesRead <= 0) break;

        if (!EVP_DigestUpdate(md_ctx_.get(), inBuf.data(), static_cast<int>(bytesRead))) throw std::runtime_error("EVP_DigestUpdate failed");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;

    if (!EVP_DigestFinal_ex(md_ctx_.get(), hash, &hashLen)) throw std::runtime_error("EVP_DigestFinal_ex failed");
    
    std::ostringstream oss;
    oss << std::hex              // output in hexadecimal format
        << std::setfill('0');    // fill missing digits with '0'

    for (unsigned int i = 0; i < hashLen; ++i)
        // "%02x" → two digits, leading zeros, lowercase
        oss << std::setw(2)
            << static_cast<unsigned int>(hash[i]);  // not char

    return oss.str();
}

AesCipherParams CryptoGuardCtx::PImpl::CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) throw std::runtime_error{"Failed to create a key from password"};

    return params;
}

void CryptoGuardCtx::PImpl::ApplyCryptoOperation(
    std::istream &inStream, 
    std::ostream &outStream,
    const AesCipherParams& params) 
{
    if (!EVP_CipherInit_ex(chiper_ctx_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), static_cast<int>(params.encrypt))) {
        throw std::runtime_error{"Failed to inicialised"};
    }

    const std::size_t BUF_SIZE = 4096;
    std::vector<unsigned char> inBuf(BUF_SIZE);
    std::vector<unsigned char> outBuf(BUF_SIZE + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    
    if (inStream.bad()) throw std::runtime_error("Stream read error (badbit set)");
    while (inStream) {
        inStream.read(reinterpret_cast<char*>(inBuf.data()), BUF_SIZE);
        std::streamsize bytesRead = inStream.gcount();
        if (inStream.bad()) throw std::runtime_error("Stream read error (badbit set)");

        if (bytesRead <= 0) break;

        if (!EVP_CipherUpdate(chiper_ctx_.get(),
                          outBuf.data(),
                          &outLen,
                          inBuf.data(),
                          static_cast<int>(bytesRead)))
        throw std::runtime_error("EVP_CipherUpdate failed");

        if (outLen > 0 )
        {
            outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
            if (!outStream) throw std::runtime_error("Stream write error");
        }
    }

    if (!EVP_CipherFinal_ex(chiper_ctx_.get(), outBuf.data(), &outLen)) throw std::runtime_error("EVP_CipherFinal_ex failed");

    if (outLen > 0)
    {
        outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
        if (!outStream) throw std::runtime_error("Stream write error");
    }
}

CryptoGuardCtx::CryptoGuardCtx() : impl_(std::make_unique<PImpl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() =default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password)
{
    impl_->EncryptFile(inStream,outStream,password);
}

void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password)
{
    impl_->DecryptFile(inStream,outStream,password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream)
{
    return impl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
