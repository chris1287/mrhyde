#include <glog/logging.h>
#include <gflags/gflags.h>
#include <sodium.h>
#include "config.h"

DEFINE_string(encrypt, "", "encrypt file");
DEFINE_string(decrypt, "", "decrypt file");
DEFINE_string(out, "", "output file");

int main(int argc, char *argv[]) {
    google::InitGoogleLogging(argv[0]);

    std::string usage = "encrypt or decrypt a file. Usage:\n";
    usage += argv[0] + std::string(" --encrypt file.txt --out file.txt.enc\n");
    usage += argv[0] + std::string(" --decrypt file.txt.enc --out file.txt\n");
    gflags::SetUsageMessage(usage);

    gflags::ParseCommandLineFlags(&argc, &argv, true);
    gflags::ShutDownCommandLineFlags();

    LOG(INFO) << "start " << FULL_APPLICATION_NAME;

    if(sodium_init() < 0) {
        LOG(ERROR) << "cannot initialize libsodium";
        return EXIT_FAILURE;
    }

    if(!FLAGS_encrypt.empty() && ! FLAGS_out.empty()) {
        LOG(INFO) << "encrypt file " << FLAGS_encrypt << " to " << FLAGS_out;
    }

    if(!FLAGS_decrypt.empty() && ! FLAGS_out.empty()) {
        LOG(INFO) << "decrypt file " << FLAGS_decrypt << " to " << FLAGS_out;
    }

    LOG(INFO) << "stop " << FULL_APPLICATION_NAME;
    return EXIT_SUCCESS;
}
