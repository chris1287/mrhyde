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
        sizeof(key),
        password.c_str(),
        password.size(),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
            LOG(ERROR) << "cannot derive password";
            return EXIT_FAILURE;
    }

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

    if(fwrite(salt, 1, crypto_pwhash_SALTBYTES, out) != crypto_pwhash_SALTBYTES) {
        LOG(ERROR) << "cannot write salt to file";
        fclose(in);
        fclose(out);
        return EXIT_FAILURE;
    }

    if(fwrite(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, out) != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        LOG(ERROR) << "cannot write encryption header to file";
        fclose(in);
        fclose(out);
        return EXIT_FAILURE;
    }

    unsigned char clear[BUFSIZ];
    unsigned char enc[sizeof(clear) + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t nin = 0;
    bool done = false;
    while(!done) {
        VLOG(1) << "read chunk";
        nin = fread(clear, 1, sizeof(clear), in);
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

        auto nout  = fwrite(enc, 1, enc_len, out);
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

int decrypt(std::string filename_in, std::string filename_out, std::string password) {
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

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

    if(fread(salt, 1, crypto_pwhash_SALTBYTES, in) != crypto_pwhash_SALTBYTES) {
        LOG(ERROR) << "cannot read salt from file";
        fclose(in);
        fclose(out);
        return EXIT_FAILURE;
    }

    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if(fread(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, in) != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        LOG(ERROR) << "cannot read encryption header from file";
        fclose(in);
        fclose(out);
        return EXIT_FAILURE;
    }

    if(crypto_pwhash(
        key,
        sizeof(key),
        password.c_str(),
        password.size(),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
            LOG(ERROR) << "cannot derive password";
            return EXIT_FAILURE;
    }

    crypto_secretstream_xchacha20poly1305_state state;
    if(crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0) {
        LOG(ERROR) << "cannot initialize decryption function";
        return EXIT_FAILURE;
    };

    VLOG(1) << "decryption function initialized";

    unsigned char clear[BUFSIZ];
    unsigned char enc[sizeof(clear) + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t nin = 0;
    bool done = false;
    while(!done) {
        VLOG(1) << "read chunk";
        nin = fread(enc, sizeof(unsigned char), sizeof(enc), in);
        if(nin < 0) {
            LOG(ERROR) << "read chunk failed";
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        if(nin != sizeof(enc)) {
            VLOG(1) << "file read completed, read " << nin << " bytes";
        }

        memset(clear, 0, sizeof(clear));
        unsigned long long dec_len = 0;
        unsigned char tag = 0;

        if(crypto_secretstream_xchacha20poly1305_pull(
            &state, 
            clear, 
            &dec_len, 
            &tag,
            enc, 
            nin,
            NULL, 
            0) != 0) {
            LOG(ERROR) << "chunk decryption failed";
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        auto nout  = fwrite(clear, sizeof(unsigned char), dec_len, out);
        if(nout != dec_len) {
            LOG(ERROR) << "cannot write decrypted chunk";
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        VLOG(1) << "decrypted chunk written: in=" << nin << ", out=" << nout << ", desired_out=" << dec_len;

        if(nin < sizeof(enc) || tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            done = true;
        }
    }
    fclose(in);
    fclose(out);

    LOG(INFO) << "decryption completed";

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    google::InitGoogleLogging(argv[0]);

    std::string usage = "encrypt or decrypt a file with a password. Usage:\n";
    usage += argv[0] + std::string(" -encrypt file.txt -out file.txt.enc -password secret\n");
    usage += argv[0] + std::string(" -decrypt file.txt.enc -out file.txt -password secret\n");
    gflags::SetUsageMessage(usage);

    gflags::ParseCommandLineFlags(&argc, &argv, true);
    gflags::ShutDownCommandLineFlags();

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
        return decrypt(FLAGS_decrypt, FLAGS_out, FLAGS_password);
    }

    return EXIT_SUCCESS;
}
