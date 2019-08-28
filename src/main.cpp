#include <cstdio>
#include <cstdlib>
#include <glog/logging.h>
#include <gflags/gflags.h>
#include <sodium.h>
#include "config.h"

DEFINE_string(encrypt, "", "encrypt file");
DEFINE_string(decrypt, "", "decrypt file");
DEFINE_string(out, "", "output file");
DEFINE_string(password, "", "encryption password");

int encrypt(std::string filename_in, std::string filename_out, std::string password) {
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    randombytes_buf(salt, sizeof(salt));

    if(crypto_pwhash(
        key,
        sizeof (key),
        password.c_str(),
        password.size(),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
            LOG(ERROR) << "cannot derive password";
            return EXIT_FAILURE;
    }

    VLOG(1) << "password derived";

    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if(crypto_secretstream_xchacha20poly1305_init_push(&state, header, key) != 0) {
        LOG(ERROR) << "cannot initialize encryption function";
        return EXIT_FAILURE;
    };

    VLOG(1) << "encryption function initialized";

    auto in = fopen(filename_in.c_str(), "rb");
    if(!in) {
        LOG(ERROR) << "cannot open file " << filename_in;
        return EXIT_FAILURE;
    }

    auto out = fopen(filename_out.c_str(), "wb");
    if(!out) {
        LOG(ERROR) << "cannot open file " << filename_out;
        fclose(out);
        return EXIT_FAILURE;
    }

    unsigned char clear[BUFSIZ];
    unsigned char enc[sizeof(clear) + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t nin = 0;
    bool done = false;
    while(!done) {
        VLOG(1) << "read chunk";
        nin = fread(clear, sizeof(unsigned char), sizeof(clear), in);
        if(nin < 0) {
            LOG(ERROR) << "read chunk failed";
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        int tag = 0;
        if(nin != sizeof(clear)) {
            VLOG(1) << "file read completed";
            tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
            done = true;
        }

        memset(enc, 0, sizeof(enc));
        unsigned long long enc_len = 0;
        if(crypto_secretstream_xchacha20poly1305_push(
            &state, 
            enc, 
            &enc_len, 
            clear, 
            nin,
            NULL, 
            0, 
            tag) != 0) {
            LOG(ERROR) << "chunk encryption failed";
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        auto nout  = fwrite(enc, sizeof(unsigned char), enc_len, out);
        if(nout != enc_len) {
            LOG(ERROR) << "cannot write encrypted chunk";
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        VLOG(1) << "encrypted chunk written: in=" << nin << ", out=" << nout << ", desired_out=" << enc_len;
    }
    fclose(in);
    fclose(out);

    LOG(INFO) << "encryption completed";

    return EXIT_SUCCESS;
}

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
        return encrypt(FLAGS_encrypt, FLAGS_out, FLAGS_password);
    }

    if(!FLAGS_decrypt.empty() && ! FLAGS_out.empty()) {
        LOG(INFO) << "decrypt file " << FLAGS_decrypt << " to " << FLAGS_out;
    }

    LOG(INFO) << "stop " << FULL_APPLICATION_NAME;
    return EXIT_SUCCESS;
}
