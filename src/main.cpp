#include <glog/logging.h>
#include "config.h"

int main(int argc, char *argv[]) {
    LOG(INFO) << "start " << FULL_APPLICATION_NAME;
    LOG(INFO) << "stop " << FULL_APPLICATION_NAME;
    return 0;
}
