#include <glog/logging.h>
#include <sodium.h>
#include "config.h"

int main(int argc, char *argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;

    LOG(INFO) << "start " << FULL_APPLICATION_NAME;

    if(sodium_init() < 0) {
        LOG(ERROR) << "cannot initialize libsodium";
        return EXIT_FAILURE;
    }

    LOG(INFO) << "stop " << FULL_APPLICATION_NAME;
    return EXIT_SUCCESS;
}
