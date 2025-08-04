#pragma once

#include <boost/program_options.hpp>
#include <optional>

using namespace std::literals; 

enum class Command { 
    Encrypt, 
    Decrypt, 
    Checksum 
};

struct Args {
    std::string input;
    std::string output;
    Command command;
    std::string password;
}; 

Command parseCommand(const std::string& str);
[[nodiscard]] std::optional<Args> ParseCommandLine(int argc, const char* const argv[]);