#include "crypto_guard_ctx.h"

namespace CryptoGuard {

class CryptoGuardCtx::PImpl {
public:
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }
};

CryptoGuardCtx::CryptoGuardCtx() : impl_(std::make_unique<PImpl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() =default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{
    impl_->EncryptFile(inStream,outStream,password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{
    impl_->DecryptFile(inStream,outStream,password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream)
{
    return impl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
