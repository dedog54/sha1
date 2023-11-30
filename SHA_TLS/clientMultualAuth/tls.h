#ifndef TLS_CONN
#define TLS_CONN

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <vector>
#include <random>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <sys/time.h>
#include <iomanip>
#include "sha1.h"
#include <cstring>

class TLSConnection{
    private: 
        const char* SERVER_IP;
        const char* ca_cert;
        const char* server_cert;
        const char* server_key;
        const int  SERVER_PORT;
        SSL_CTX* sslContext;
        std::string authData;
        SSL* ssl;
        int clientSocket;
    public: 
        TLSConnection(const char* SERVER_IP, const int SERVER_PORT, const char* ca_cert, 
            const char* server_cert, const char* server_key);

        void initialConnection();
        void handShakeWithServer();
        void closeConnection();
}; 

#endif /* TLS_CONN */