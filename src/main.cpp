#include <cstdio>
#include <cstdlib>
#include <spdlog/spdlog.h>
#include <spdlog/cfg/env.h>
#include <sodium.h>
#include <iostream>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>
#include "config.h"

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
        crypto_pwhash_OPSLIMIT_SENSITIVE,
        crypto_pwhash_MEMLIMIT_SENSITIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
            spdlog::error("cannot derive password");
            return EXIT_FAILURE;
    }

    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if(crypto_secretstream_xchacha20poly1305_init_push(&state, header, key) != 0) {
        spdlog::error("cannot initialize encryption function");
        return EXIT_FAILURE;
    };

    spdlog::debug("encryption function initialized");

    auto in = fopen(filename_in.c_str(), "rb");
    if(!in) {
        spdlog::error("cannot open file {}", filename_in);
        return EXIT_FAILURE;
    }

    auto out = fopen(filename_out.c_str(), "wb");
    if(!out) {
        spdlog::error("cannot open file {}", filename_out);
        fclose(out);
        return EXIT_FAILURE;
    }

    if(fwrite(salt, 1, crypto_pwhash_SALTBYTES, out) != crypto_pwhash_SALTBYTES) {
        spdlog::error("cannot write salt to file");
        fclose(in);
        fclose(out);
        return EXIT_FAILURE;
    }

    if(fwrite(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, out) != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        spdlog::error("cannot write encryption header to file");
        fclose(in);
        fclose(out);
        return EXIT_FAILURE;
    }

    unsigned char clear[BUFSIZ];
    unsigned char enc[sizeof(clear) + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t nin = 0;
    bool done = false;
    while(!done) {
        spdlog::debug("read chunk");
        nin = fread(clear, 1, sizeof(clear), in);
        if(nin < 0) {
            spdlog::error("read chunk failed");
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        int tag = 0;
        if(nin != sizeof(clear)) {
            spdlog::debug("file read completed");
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
            spdlog::error("chunk encryption failed");
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        auto nout  = fwrite(enc, 1, enc_len, out);
        if(nout != enc_len) {
            spdlog::error("cannot write encrypted chunk");
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        spdlog::debug("encrypted chunk written: in={}, out={}, desired_out={}", std::to_string(nin), std::to_string(nout), std::to_string(enc_len));
    }
    fclose(in);
    fclose(out);

    spdlog::info("encryption completed");

    return EXIT_SUCCESS;
}

int decrypt(std::string filename_in, std::string filename_out, std::string password) {
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    auto in = fopen(filename_in.c_str(), "rb");
    if(!in) {
        spdlog::error("cannot open file {}", filename_in);
        return EXIT_FAILURE;
    }

    auto out = fopen(filename_out.c_str(), "wb");
    if(!out) {
        spdlog::error("cannot open file {}", filename_out);
        fclose(out);
        return EXIT_FAILURE;
    }

    if(fread(salt, 1, crypto_pwhash_SALTBYTES, in) != crypto_pwhash_SALTBYTES) {
        spdlog::error("cannot read salt from file");
        fclose(in);
        fclose(out);
        return EXIT_FAILURE;
    }

    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if(fread(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, in) != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        spdlog::error("cannot read encryption header from file");
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
        crypto_pwhash_OPSLIMIT_SENSITIVE,
        crypto_pwhash_MEMLIMIT_SENSITIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
            spdlog::error("cannot derive password");
            return EXIT_FAILURE;
    }

    crypto_secretstream_xchacha20poly1305_state state;
    if(crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0) {
        spdlog::error("cannot initialize decryption function");
        return EXIT_FAILURE;
    };

    spdlog::debug("decryption function initialized");

    unsigned char clear[BUFSIZ];
    unsigned char enc[sizeof(clear) + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t nin = 0;
    bool done = false;
    while(!done) {
        spdlog::debug("read chunk");
        nin = fread(enc, sizeof(unsigned char), sizeof(enc), in);
        if(nin < 0) {
            spdlog::error("read chunk failed");
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        if(nin != sizeof(enc)) {
            spdlog::debug("file read completed, read {} bytes", std::to_string(nin));
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
            spdlog::error("chunk decryption failed");
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        auto nout  = fwrite(clear, sizeof(unsigned char), dec_len, out);
        if(nout != dec_len) {
            spdlog::error("cannot write decrypted chunk");
            fclose(in);
            fclose(out);
            return EXIT_FAILURE;
        }

        spdlog::debug("decrypted chunk written: in={}, out={}, desired_out={}", std::to_string(nin), std::to_string(nout), std::to_string(dec_len));

        if(nin < sizeof(enc) || tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            done = true;
        }
    }
    fclose(in);
    fclose(out);

    spdlog::info("decryption completed");

    return EXIT_SUCCESS;
}

char *read_password(size_t const password_size) {
    struct termios oflags, nflags;
    auto password = static_cast<char *>(sodium_malloc(password_size));
    if(!password) {
        spdlog::error("memory error");
        exit(1);
    }
    printf("enter password: ");
    fflush(stdout);
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;
    if(tcsetattr(fileno(stdin), TCSANOW, &nflags)) {
        spdlog::error("tcsetattr set error");
        sodium_free(password);
        exit(1);
    }
    size_t idx = 0;
    do {
        if(read(fileno(stdin), &password[idx], sizeof(char)) != 1) {
            spdlog::error("read password error");
            sodium_free(password);
            exit(1);
        }
        if(password[idx] == '\n') {
            password[idx] = '\0';
            break;
        }
        idx++;
    } while(idx < password_size-1);
    password[password_size-1] = '\0';

    if(tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
        spdlog::error("tcsetattr reset error");
        sodium_free(password);
        exit(1);
    }

    return password;
}

void help(std::string const &name) {
    std::cerr
    << "Usage:" << std::endl
    << name << " --encrypt file.dec.bin --out file.enc.bin" << std::endl
    << name << " --decrypt file.enc.bin --out file.dec.bin" << std::endl
    << std::endl;
}

int main(int argc, char *argv[]) {
    spdlog::cfg::load_env_levels();

    if(sodium_init() < 0) {
        spdlog::error("cannot initialize libsodium");
        return EXIT_FAILURE;
    } else {
        spdlog::debug("libsodium has been initialized");
    }

    struct option long_options[] = {
        {"help",        no_argument,       0, 'h'},
        {"encrypt",     required_argument, 0, 'e'},
        {"decrypt",     required_argument, 0, 'd'},
        {"out",         required_argument, 0, 'o'},
        {0,             0,                 0, 0}
    };

    bool do_encrypt = false;
    bool do_decrypt = false;
    std::string file_in = "input.bin";
    std::string file_out = "output.bin";

    int idx = 0;
    while(true) {
        int x = getopt_long(argc, argv, "he:d:o:p:", long_options, &idx);
        if(x < 0) {
            break;
        }

        switch(x) {
            case 'h': {
                help(argv[0]);
                exit(0);
            }
            case 'e': {
                do_encrypt = true;
                file_in = optarg;
                break;
            }
            case 'd': {
                do_decrypt = true;
                file_in = optarg;
                break;
            }
            case 'o': {
                file_out = optarg;
                break;
            }
            default: {
                help(argv[0]);
                exit(1);
            }
        }
    }

    if((do_decrypt && do_encrypt) || (!do_encrypt && !do_decrypt)) {
        spdlog::error("either encrypt or decrypt option must be used");
        help(argv[0]);
        exit(1);
    }

    auto password = read_password(64);

    int res = 0;

    if(do_encrypt) {
        spdlog::info("encrypt file {} to {}", file_in, file_out);
        res = encrypt(file_in, file_out, password);
    } else if(do_decrypt) {
        spdlog::info("decrypt file {} to {}", file_in, file_out);
        res = decrypt(file_in, file_out, password);
    }

    sodium_free(password);

    return res;
}
