#include <gtest/gtest.h>

#include "program_options.h"

#include <boost/program_options.hpp>

const char* programName = "./programName";
const char* helpOpt = "--help";
const char* commandOpt = "--command";
const char* inputOpt = "--input";
const char* outputOpt = "--output";
const char* passwordOpt = "--password";
const char* inputFileName = "inputFileName";
const char* outputFileName = "outputFileName";
const char* password = "password";

const char* commandEncrypt = "encrypt";
const char* commandDecrypt = "decrypt"; 
const char* commandChecksum = "checksum";
const char* wrongCommand = "wrongCommand";

TEST(ProgramOptions, ThrowsIfRequiredFieldsMissing) 
{
    const char* noOptions[] = {programName};
    EXPECT_ANY_THROW(auto args = ParseCommandLine(1,noOptions)); 

    const char* allOutputOption[] = {programName,commandOpt,commandEncrypt,inputOpt,inputFileName,outputOpt,outputFileName,passwordOpt,password};
    EXPECT_NO_THROW(auto args = ParseCommandLine(9,allOutputOption)); 

    const char* defaultOutputOption[] = {programName,commandOpt,commandEncrypt,inputOpt,inputFileName,passwordOpt,password};
    EXPECT_NO_THROW(auto args = ParseCommandLine(7,defaultOutputOption)); 

    using parrametrError = boost::program_options::invalid_command_line_syntax;
    using validationError = boost::program_options::validation_error;
    
    // check output Option
    const char* noOutputOptionArgument[] = {programName,commandOpt,commandEncrypt,inputOpt,inputFileName,passwordOpt,password,outputOpt};
    EXPECT_THROW(auto args = ParseCommandLine(8,noOutputOptionArgument),parrametrError); 

    // check input Option
    const char* noInputOption[] = {programName,commandOpt,commandEncrypt,passwordOpt,password};
    EXPECT_THROW(auto args = ParseCommandLine(5,noInputOption), std::runtime_error); 
    const char* noInputOptionArgument[] = {programName,commandOpt,commandEncrypt,passwordOpt,password,inputOpt};
    EXPECT_THROW(auto args = ParseCommandLine(6,noInputOptionArgument),parrametrError);

    // check passsword Option
    const char* noPassswordOption[] = {programName,commandOpt,commandEncrypt,inputOpt,inputFileName};
    EXPECT_THROW(auto args = ParseCommandLine(5,noPassswordOption), std::runtime_error); 
    const char* noPassswordOptionArgument[] = {programName,commandOpt,commandEncrypt,inputOpt,inputFileName,passwordOpt};
    EXPECT_THROW(auto args = ParseCommandLine(6,noPassswordOptionArgument),parrametrError);

    //check command Option
    const char* noCommandOption[] = {programName,inputOpt,inputFileName,passwordOpt,password};
    EXPECT_THROW(auto args = ParseCommandLine(5,noCommandOption), std::runtime_error); 
    const char* noCommandOptionArgument[] = {programName,inputOpt,inputFileName,passwordOpt,password,commandOpt};
    EXPECT_THROW(auto args = ParseCommandLine(6,noCommandOptionArgument),parrametrError);

    //check command arguments
    const char* commandOptionArgumentEncrypt[] = {programName,inputOpt,inputFileName,passwordOpt,password,commandOpt,commandEncrypt};
    EXPECT_NO_THROW(auto args = ParseCommandLine(7,commandOptionArgumentEncrypt));
    const char* commandOptionArgumentDecrypt[] = {programName,inputOpt,inputFileName,passwordOpt,password,commandOpt,commandDecrypt};
    EXPECT_NO_THROW(auto args = ParseCommandLine(7,commandOptionArgumentDecrypt));
    const char* commandOptionArgumentChecksum[] = {programName,inputOpt,inputFileName,passwordOpt,password,commandOpt,commandChecksum};
    EXPECT_NO_THROW(auto args = ParseCommandLine(7,commandOptionArgumentChecksum));
    //check wrong command arguments
    const char* wrongCommandOptionArgument[] = {programName,inputOpt,inputFileName,passwordOpt,password,commandOpt,wrongCommand};
    EXPECT_THROW(auto args = ParseCommandLine(7,wrongCommandOptionArgument), validationError);
}

TEST(ProgramOptions, CheckParsedArguments) 
{
    const char* allOutputOption[] = {programName,commandOpt,commandEncrypt,inputOpt,inputFileName,outputOpt,outputFileName,passwordOpt,password};
    auto args = ParseCommandLine(9,allOutputOption);

    EXPECT_EQ (args->input,inputFileName);
    EXPECT_EQ (args->output,outputFileName);
    EXPECT_EQ (args->password,password);
    EXPECT_EQ (args->command, Command::Encrypt);

    const char* allOutputOptionCommandDecrypt[] = {programName,commandOpt,commandDecrypt,inputOpt,inputFileName,outputOpt,outputFileName,passwordOpt,password};
    args = ParseCommandLine(9,allOutputOptionCommandDecrypt);
    EXPECT_EQ (args->command, Command::Decrypt);

    const char* allOutputOptionCommandChecksum[] = {programName,commandOpt,commandChecksum,inputOpt,inputFileName,outputOpt,outputFileName,passwordOpt,password};
    args = ParseCommandLine(9,allOutputOptionCommandChecksum);
    EXPECT_EQ (args->command, Command::Checksum);
}