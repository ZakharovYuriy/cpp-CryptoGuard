#include <gtest/gtest.h>

#include "cmd_options.h"

#include <boost/program_options.hpp>

namespace {
const char *programName = "./programName";
const char *helpOpt = "--help";
const char *commandOpt = "--command";
const char *inputOpt = "--input";
const char *outputOpt = "--output";
const char *passwordOpt = "--password";
const char *inputFileName = "inputFileName";
const char *outputFileName = "outputFileName";
const char *password = "password";

const char *commandEncrypt = "encrypt";
const char *commandDecrypt = "decrypt";
const char *commandChecksum = "checksum";
const char *wrongCommand = "wrongCommand";

const char *defaultOutputFilePtah = "./result.txt";
}  // namespace

using namespace ::CryptoGuard;
using Command = CryptoGuard::ProgramOptions::COMMAND_TYPE;

// Aliases for expected exception types (kept near the top for reuse)
using parameterError = boost::program_options::invalid_command_line_syntax;
using validationError = boost::program_options::validation_error;
using requiredFeildError = boost::program_options::required_option;

// --- Missing/Help cases ---

TEST(ProgramOptions, ThrowsWhenNoOptionsProvided) {
    // No options at all → should throw due to missing required options
    const char* noOptions[] = {programName};
    EXPECT_ANY_THROW(ProgramOptions programOptions(1, noOptions));
}

TEST(ProgramOptions, ThrowsHelpRequestedWhenOnlyHelpOption) {
    // Only --help → should throw a dedicated HelpRequested exception
    const char* onlyHelpOption[] = {programName, helpOpt};
    EXPECT_THROW(ProgramOptions programOptions(2, onlyHelpOption), HelpRequested);
}

// --- Valid cases ---

TEST(ProgramOptions, NoThrow_AllRequiredOptionsWithExplicitOutput) {
    // All required options including explicit output → should not throw
    const char* allOutputOption[] = {
        programName, commandOpt, commandEncrypt, inputOpt, inputFileName,
        outputOpt, outputFileName, passwordOpt, password
    };
    EXPECT_NO_THROW(ProgramOptions programOptions(9, allOutputOption));
}

TEST(ProgramOptions, NoThrow_OutputOmittedUsesDefault) {
    // Output option omitted → should use default value and not throw
    const char* defaultOutputOption[] = {
        programName, commandOpt, commandEncrypt, inputOpt,
        inputFileName, passwordOpt, password
    };
    EXPECT_NO_THROW(ProgramOptions programOptions(7, defaultOutputOption));
}

// --- Output option edge cases ---

TEST(ProgramOptions, ThrowsWhenOutputArgumentMissing) {
    // Output flag present but its argument is missing
    const char* noOutputOptionArgument[] = {
        programName, commandOpt, commandEncrypt, inputOpt,
        inputFileName, passwordOpt, password, outputOpt
    };
    EXPECT_THROW(ProgramOptions programOptions(8, noOutputOptionArgument), parameterError);
}

// --- Input option edge cases ---

TEST(ProgramOptions, ThrowsWhenInputOptionMissingEntirely) {
    // Missing --input option and its argument
    const char* noInputOption[] = {
        programName, commandOpt, commandEncrypt, passwordOpt, password
    };
    EXPECT_THROW(ProgramOptions programOptions(5, noInputOption), requiredFeildError);
}

TEST(ProgramOptions, ThrowsWhenInputArgumentMissing) {
    // --input provided without an argument
    const char* noInputOptionArgument[] = {
        programName, commandOpt, commandEncrypt, passwordOpt, password, inputOpt
    };
    EXPECT_THROW(ProgramOptions programOptions(6, noInputOptionArgument), parameterError);
}

// --- Password option edge cases ---

TEST(ProgramOptions, ThrowsWhenPasswordOptionMissingEntirely) {
    // Missing --password option and its argument
    const char* noPasswordOption[] = {
        programName, commandOpt, commandEncrypt, inputOpt, inputFileName
    };
    EXPECT_THROW(ProgramOptions programOptions(5, noPasswordOption), std::runtime_error);
}

TEST(ProgramOptions, ThrowsWhenPasswordArgumentMissing) {
    // --password provided without an argument
    const char* noPasswordOptionArgument[] = {
        programName, commandOpt, commandEncrypt,
        inputOpt, inputFileName, passwordOpt
    };
    EXPECT_THROW(ProgramOptions programOptions(6, noPasswordOptionArgument), parameterError);
}

// --- Command option edge cases ---

TEST(ProgramOptions, ThrowsWhenCommandOptionMissingEntirely) {
    // Missing --command option and its argument
    const char* noCommandOption[] = {
        programName, inputOpt, inputFileName, passwordOpt, password
    };
    EXPECT_THROW(ProgramOptions programOptions(5, noCommandOption), requiredFeildError);
}

TEST(ProgramOptions, ThrowsWhenCommandArgumentMissing) {
    // --command provided without an argument
    const char* noCommandOptionArgument[] = {
        programName, inputOpt, inputFileName, passwordOpt, password, commandOpt
    };
    EXPECT_THROW(ProgramOptions programOptions(6, noCommandOptionArgument), parameterError);
}

// --- Valid command values ---

TEST(ProgramOptions, NoThrow_CommandEncrypt) {
    const char* args[] = {
        programName, inputOpt, inputFileName, passwordOpt,
        password, commandOpt, commandEncrypt
    };
    EXPECT_NO_THROW(ProgramOptions programOptions(7, args));
}

TEST(ProgramOptions, NoThrow_CommandDecrypt) {
    const char* args[] = {
        programName, inputOpt, inputFileName, passwordOpt,
        password, commandOpt, commandDecrypt
    };
    EXPECT_NO_THROW(ProgramOptions programOptions(7, args));
}

TEST(ProgramOptions, NoThrow_CommandChecksum) {
    const char* args[] = {
        programName, inputOpt, inputFileName, passwordOpt,
        password, commandOpt, commandChecksum
    };
    EXPECT_NO_THROW(ProgramOptions programOptions(7, args));
}

// --- Invalid command value ---

TEST(ProgramOptions, ThrowsWhenCommandValueInvalid) {
    // Command argument is not one of encrypt/decrypt/checksum
    const char* wrongCommandOptionArgument[] = {
        programName, inputOpt, inputFileName, passwordOpt,
        password, commandOpt, wrongCommand
    };
    EXPECT_THROW(ProgramOptions programOptions(7, wrongCommandOptionArgument), validationError);
}

// --- Semantic validation ---

TEST(ProgramOptions, ThrowsWhenInputEqualsOutput) {
    // Parsed arguments validation: input file must differ from output file
    const char* inputEqualsOutputOptionCommand[] = {
        programName, commandOpt, commandDecrypt, inputOpt, inputFileName,
        outputOpt,   inputFileName, passwordOpt, password
    };
    EXPECT_THROW(ProgramOptions programOptions(9, inputEqualsOutputOptionCommand), std::runtime_error);
}

// Check Parsed Arguments all options with ENCRYPT command
TEST(ProgramOptions, CheckAllOptionsWithEncryptCommand) {
    const char *allOutputOption[] = {programName, commandOpt,     commandEncrypt, inputOpt, inputFileName,
                                        outputOpt,   outputFileName, passwordOpt,    password};
    ProgramOptions programOptions(9, allOutputOption);

    EXPECT_EQ(programOptions.GetInputFile(), inputFileName);
    EXPECT_EQ(programOptions.GetOutputFile(), outputFileName);
    EXPECT_EQ(programOptions.GetPassword(), password);
    EXPECT_EQ(programOptions.GetCommand(), Command::ENCRYPT);
}

// Check Parsed Arguments all options with DECRYPT command
TEST(ProgramOptions, CheckDecryptCommandParsing) {
        const char *allOutputOptionCommand[] = {programName, commandOpt,     commandDecrypt, inputOpt, inputFileName,
                                                outputOpt,   outputFileName, passwordOpt,    password};
        ProgramOptions programOptions(9, allOutputOptionCommand);
        EXPECT_EQ(programOptions.GetCommand(), Command::DECRYPT);
}

// Check Parsed Arguments all options with CHECKSUM command
TEST(ProgramOptions, CheckChecksumCommandParsing) {
    const char *allOutputOptionCommand[] = {programName, commandOpt,     commandChecksum, inputOpt, inputFileName,
                                            outputOpt,   outputFileName, passwordOpt,     password};
    ProgramOptions programOptions(9, allOutputOptionCommand);
    EXPECT_EQ(programOptions.GetCommand(), Command::CHECKSUM);
}

// Check Parsed Arguments with CHECKSUM command (only required fields)
TEST(ProgramOptions, CheckChecksumCommandRequiredFieldsParsing) {
    const char *requiredOutputOptionCommand[] = {programName, commandOpt, commandChecksum, inputOpt, inputFileName};
                                            
    EXPECT_NO_THROW(ProgramOptions programOptions(5, requiredOutputOptionCommand));
    ProgramOptions programOptions(5, requiredOutputOptionCommand);
    EXPECT_EQ(programOptions.GetCommand(), Command::CHECKSUM);
}

// Check Parsed Arguments default output path when output option is not provided
TEST(ProgramOptions, CheckDefaultOutputPathWhenNoOutputOption) {
    const char *allOutputOption[] = {programName,   commandOpt,  commandEncrypt, inputOpt,
                                        inputFileName, passwordOpt, password};
    ProgramOptions programOptions(7, allOutputOption);

    EXPECT_EQ(programOptions.GetOutputFile(), defaultOutputFilePtah);
}