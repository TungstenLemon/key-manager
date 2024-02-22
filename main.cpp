#include <sodium.h>
#include <stdio.h>
#include <iostream>

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#define KEY_LEN crypto_secretstream_xchacha20poly1305_KEYBYTES
#define CHUNK_SIZE 4096

void SetStdinEcho(bool enable = true) {
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if( !enable )
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode );

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

static int encrypt(const char *target_file, const char *source_file, 
const char *PASSWORD) {
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[KEY_LEN];
    randombytes_buf(salt, sizeof salt);
    if (crypto_pwhash(key, sizeof key, PASSWORD, strlen(PASSWORD), salt,
     crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE,
     crypto_pwhash_ALG_DEFAULT) != 0) {
        return 1;
     }
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;
    FILE          *destination, *source;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;
    source = fopen(source_file, "rb");
    destination = fopen(target_file, "wb");
    fwrite(salt, 1, crypto_pwhash_SALTBYTES, destination);
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
    fwrite(header, 1, sizeof header, destination);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, source);
        eof = feof(source);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&state, buf_out, &out_len, buf_in, rlen,
                                                   NULL, 0, tag);
        fwrite(buf_out, 1, (size_t) out_len, destination);
    } while (! eof);
    fclose(destination);
    fclose(source);
    return 0;
}


static int
decrypt(const char *target_file, const char *source_file,
        const char *PASSWORD) {
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[KEY_LEN];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE          *destination, *source;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    source = fopen(source_file, "rb");
    destination = fopen(target_file, "wb");
    fread(salt, 1, sizeof salt, source);
    if (crypto_pwhash(key, sizeof key, PASSWORD, strlen(PASSWORD), salt,
     crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE,
     crypto_pwhash_ALG_DEFAULT) != 0) {
        return 1;
     }
    fread(header, 1, sizeof header, source);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, source);
        eof = feof(source);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                                                       buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            if (! eof) {
                goto ret; /* end of stream reached before the end of the file */
            }
        } else { /* not the final chunk yet */
            if (eof) {
                goto ret; /* end of file reached before the end of the stream */
            }
        }
        fwrite(buf_out, 1, (size_t) out_len, destination);
    } while (! eof);

    ret = 0;
ret:
    fclose(destination);
    fclose(source);
    return ret;
}

int main(int argc, char * argv[]) {
    bool mode = true;
    if( argc != 4) {
        std::cerr << "Wrong Usage"; 
        return 1;
    }
    if (sodium_init() == -1) {
        return 1;
    }
    SetStdinEcho(false);
    int PASSWORD_LEN;
    std::cout << "Input password length in characters: \n"; 
    std::cin >> PASSWORD_LEN;
    std::cout << "Input password: \n"; 
    char PASSWORD[PASSWORD_LEN+1];
    fflush (stdin);
    fgets(PASSWORD, PASSWORD_LEN+1, stdin);
    SetStdinEcho(true);
    if( std::strcmp( argv[1], "-encrypt" ) == 0 ) {
        if (encrypt(argv[3], argv[2], PASSWORD) != 0) {
        return 1;
        }
    } else if( std::strcmp( argv[1], "-decrypt" ) == 0 ) {
        if (decrypt(argv[3], argv[2], PASSWORD) != 0) {
        return 1;
        }
    } else {
        std::cerr << "Wrong Usage"; 
        return 1;
    }

    return 0;
}