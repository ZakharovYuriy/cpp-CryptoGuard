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

TEST(ProgramOptions, ThrowsIfRequiredFieldsMissing) {
    // no options passed at all → should throw due to missing required options
    const char *noOptions[] = {programName};
    EXPECT_ANY_THROW(ProgramOptions programOptions(1, noOptions));

    // Check that creating ProgramOptions with only the help option does not throw an exception
    const char *onlyHelpOption[] = {programName, helpOpt};
    EXPECT_THROW(ProgramOptions programOptions(2, onlyHelpOption), HelpRequested);

    // all required options including output explicitly provided → should not throw
    const char *allOutputOption[] = {programName, commandOpt,     commandEncrypt, inputOpt, inputFileName,
                                     outputOpt,   outputFileName, passwordOpt,    password};
    EXPECT_NO_THROW(ProgramOptions programOptions(9, allOutputOption));

    // output option omitted, should use default value → should not throw
    const char *defaultOutputOption[] = {programName,   commandOpt,  commandEncrypt, inputOpt,
                                         inputFileName, passwordOpt, password};
    EXPECT_NO_THROW(ProgramOptions programOptions(7, defaultOutputOption));

    // Aliases for expected exception types
    using parrametrError = boost::program_options::invalid_command_line_syntax;
    using validationError = boost::program_options::validation_error;

    // check output Option (missing argument)
    const char *noOutputOptionArgument[] = {programName,   commandOpt,  commandEncrypt, inputOpt,
                                            inputFileName, passwordOpt, password,       outputOpt};
    EXPECT_THROW(ProgramOptions programOptions(8, noOutputOptionArgument), parrametrError);

    // check input Option (missing option and argument) and (only missing argument)
    const char *noInputOption[] = {programName, commandOpt, commandEncrypt, passwordOpt, password};
    EXPECT_THROW(ProgramOptions programOptions(5, noInputOption), std::runtime_error);
    const char *noInputOptionArgument[] = {programName, commandOpt, commandEncrypt, passwordOpt, password, inputOpt};
    EXPECT_THROW(ProgramOptions programOptions(6, noInputOptionArgument), parrametrError);

    // check passsword Option (missing option and argument) and (only missing argument)
    const char *noPassswordOption[] = {programName, commandOpt, commandEncrypt, inputOpt, inputFileName};
    EXPECT_THROW(ProgramOptions programOptions(5, noPassswordOption), std::runtime_error);
    const char *noPassswordOptionArgument[] = {programName, commandOpt,    commandEncrypt,
                                               inputOpt,    inputFileName, passwordOpt};
    EXPECT_THROW(ProgramOptions programOptions(6, noPassswordOptionArgument), parrametrError);

    // check command Option (missing option and argument) and (only missing argument)
    const char *noCommandOption[] = {programName, inputOpt, inputFileName, passwordOpt, password};
    EXPECT_THROW(ProgramOptions programOptions(5, noCommandOption), std::runtime_error);
    const char *noCommandOptionArgument[] = {programName, inputOpt, inputFileName, passwordOpt, password, commandOpt};
    EXPECT_THROW(ProgramOptions programOptions(6, noCommandOptionArgument), parrametrError);

    // check command arguments -> valid command arguments (encrypt, decrypt, checksum) → should not throw
    const char *commandOptionArgumentEncrypt[] = {programName, inputOpt,   inputFileName, passwordOpt,
                                                  password,    commandOpt, commandEncrypt};
    EXPECT_NO_THROW(ProgramOptions programOptions(7, commandOptionArgumentEncrypt));
    const char *commandOptionArgumentDecrypt[] = {programName, inputOpt,   inputFileName, passwordOpt,
                                                  password,    commandOpt, commandDecrypt};
    EXPECT_NO_THROW(ProgramOptions programOptions(7, commandOptionArgumentDecrypt));
    const char *commandOptionArgumentChecksum[] = {programName, inputOpt,   inputFileName,  passwordOpt,
                                                   password,    commandOpt, commandChecksum};
    EXPECT_NO_THROW(ProgramOptions programOptions(7, commandOptionArgumentChecksum));
    // check wrong command arguments -> invalid command value passed (not among encrypt/decrypt/checksum) → should throw
    const char *wrongCommandOptionArgument[] = {programName, inputOpt,   inputFileName, passwordOpt,
                                                password,    commandOpt, wrongCommand};
    EXPECT_THROW(ProgramOptions programOptions(7, wrongCommandOptionArgument), validationError);

    // Check Parsed Arguments input file == output file
    const char *inputEqualsOutputOptionCommand[] = {programName, commandOpt,     commandDecrypt, inputOpt, inputFileName,
                                            outputOpt,   inputFileName, passwordOpt,    password};
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