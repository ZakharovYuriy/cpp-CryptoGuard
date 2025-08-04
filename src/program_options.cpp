#include "program_options.h"

#include <boost/program_options.hpp>
#include <iostream>
#include <optional>

using namespace std::literals; 
namespace po = boost::program_options;

Command parseCommand(const std::string& str) 
{
    if (str == "encrypt") return Command::Encrypt;
    if (str == "decrypt") return Command::Decrypt;
    if (str == "checksum") return Command::Checksum;
    throw po::validation_error(po::validation_error::invalid_option_value, "command", str);
}

[[nodiscard]] std::optional<Args> ParseCommandLine(int argc, const char* const argv[]) 
{
    po::options_description desc{"All options"s};

    Args args;
    desc.add_options()
        ("help,h", "Show help")

        ("input,i", po::value(&args.input)->value_name("file"s), "Path to the input file")

        ("output,o", po::value(&args.output)->default_value("./result.txt", "result.txt")->value_name("file"s), "The path to the file where the result will be saved")

        ("command,c", po::value<std::string>()->value_name("command"s)->notifier([&args](const std::string& s) 
        {
            args.command = parseCommand(s);
        }), "The encrypt, decrypt, or checksum command")

        ("password,p", po::value(&args.password)->value_name("password"s), "Password for encryption and decryption");

    // Create a container to store the parsed command-line options
    po::variables_map vm;

    // Parse the command-line arguments according to the description 'desc'
    // and store the result in the variables_map 'vm'
    po::store(po::parse_command_line(argc, argv, desc), vm);

    // Transfer the values from 'vm' into the variables they are linked to
    po::notify(vm);

    if (vm.contains("help"s)) {
        // If the --help parameter was specified, then output the help and return nullopt
        std::cout << desc;
        return std::nullopt;
    }

    if (!vm.contains("input"s)) {
        throw std::runtime_error("Input files have not been specified"s);
    }
    if (!vm.contains("command"s)) {
        throw std::runtime_error("Command is not specified"s);
    }
    if (!vm.contains("password"s)) {
        throw std::runtime_error("Password is not specified"s);
    }

    // Everything is fine with the program options, we return the args structure
    return args;
}