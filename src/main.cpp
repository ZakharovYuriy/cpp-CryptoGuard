#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

std::ifstream openInputBinaryFile(const std::string& filename) {
    std::ifstream inFile{filename, std::ios::binary};
    if (!inFile.is_open() || inFile.fail())
        throw std::runtime_error(
            "Cannot open file for reading: " + filename);
    return inFile;
}

std::ofstream openOutputBinaryFile(const std::string& filename) {
    std::ofstream outFile{filename, std::ios::binary};
    if (!outFile.is_open() || outFile.fail())
        throw std::runtime_error(
            "Cannot open file for writing: " + filename);
    return outFile;
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions programOptions(argc, argv);
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (programOptions.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
        {
            auto inStream = openInputBinaryFile(programOptions.GetInputFile());
            auto outStream = openOutputBinaryFile(programOptions.GetInputFile());
            cryptoCtx.EncryptFile(inStream, outStream, programOptions.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT:
        {
            auto inStream = openInputBinaryFile(programOptions.GetInputFile());
            auto outStream = openOutputBinaryFile(programOptions.GetInputFile());
            cryptoCtx.DecryptFile(inStream, outStream, programOptions.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM:
        {
            auto inStream = openInputBinaryFile(programOptions.GetInputFile());
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inStream));
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }
        
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}