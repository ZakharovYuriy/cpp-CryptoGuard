#include "cmd_options.h"

#include <boost/program_options.hpp>
#include <iostream>

using namespace std::literals;
namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions(int argc, const char *const argv[]) : desc_("Allowed options") {
    desc_.add_options()("help,h", "Show help")

        ("input,i", po::value(&inputFile_)->required()->value_name("file"s), "Path to the input file")

            ("output,o", po::value(&outputFile_)->default_value("./result.txt", "result.txt")->value_name("file"s),
             "The path to the file where the result will be saved")

                ("command,c",
                 po::value<std::string>()->required()->value_name("command"s)->notifier([this](const std::string &s) {
                     command_ = parseCommand(s);
                 }),
                 "The encrypt, decrypt, or checksum command")

                    ("password,p", po::value(&password_)->value_name("password"s),
                     "Password for encryption and decryption");

    // Create a container to store the parsed command-line options
    po::variables_map vm;

    // Parse the command-line arguments according to the description 'desc'
    // and store the result in the variables_map 'vm'
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    if (vm.contains("help"s)) {
        std::cout << desc_;
        throw HelpRequested();
    }

    // Transfer the values from 'vm' into the variables they are linked to
    po::notify(vm);

    if (!vm.contains("password"s)) {
        if (command_ != COMMAND_TYPE::CHECKSUM)
            throw std::runtime_error("Password is not specified"s);
    }
    if (inputFile_ == outputFile_) {
        throw std::runtime_error("Input file must not be the same as output file"s);
    }
}

ProgramOptions::~ProgramOptions() = default;

ProgramOptions::COMMAND_TYPE ProgramOptions::parseCommand(const std::string &str) {
    if (auto it = commandMapping_.find(str); it != commandMapping_.end())
        return it->second;
    throw po::validation_error(po::validation_error::invalid_option_value, "command", str);
}

}  // namespace CryptoGuard
