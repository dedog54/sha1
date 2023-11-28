#include <iostream>
#include <cstring>
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

#include <openssl/sha.h>

const char* SERVER_IP = "18.202.148.130";
const int SERVER_PORT = 3336;

std::string sha1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

int main(){
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    std::cout << "client is working" << std::endl;
    
    //Create an SSL context
    SSL_CTX* sslContext = SSL_CTX_new(TLS_client_method());
    if(!sslContext) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Load CA certificate of the server for verification
    if (SSL_CTX_load_verify_locations(sslContext, "ca.crt", NULL) == 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Load client certificate and private key
    if (SSL_CTX_use_certificate_file(sslContext, "client.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(sslContext, "client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    //Create a socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(clientSocket == -1){
        perror("Error creating socket");
        return -1;
    }
    
    //set up the server address structure
    struct  sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &(serverAddress.sin_addr));
    
    //Connect to the server
    if(connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1){
        ERR_print_errors_fp(stderr);
        close(clientSocket);
        return -1;
    }

    
    //Create an SSL object and associate it with the socket
    SSL* ssl = SSL_new(sslContext);
    SSL_set_fd(ssl, clientSocket);

    if(SSL_connect(ssl) <= 0){
        ERR_print_errors_fp(stderr);
        close(clientSocket);
        return -1;
    }
    
    //Main loop for sending and receiving data
    // std::string userInput;
    while (true) {
        

        //Receive and print response from the server
        char buffer[1024];
        int bytesRead = SSL_read(ssl, buffer, sizeof(buffer));
        if(bytesRead > 0){
            buffer[bytesRead] = '\0';
            std::cout << "Received from server: " << buffer << std::endl;

            std::string receivedData(buffer);
            std::stringstream ss(receivedData);
            std::string argument;
            std::vector<std::string> arguments;

            while(std::getline(ss, argument, ' ')){
                arguments.push_back(argument);
            }

            std::cout << "argument[0] is: |" << arguments[0] << "||" << std::endl; 

            if(arguments[0] == "HELO\n"){
                std::string reply = "EHLO\n";
                
                SSL_write(ssl, reply.c_str(), reply.length());
                
            } else if(arguments[0] == "ERROR"){
                // print("ERROR: " + " ".join(args[1:]))
                std::string error_str = "";
                for(int i = 1; i < arguments.size(); i++){
                    error_str += " ";
                    error_str += arguments[i];
                }
                std::cout << "ERROR: " << error_str << std::endl;
            } else if(arguments[0] == "POW"){

                std::cout << "POW is here" << std::endl;
                std::string suffix = "abecd2312";
                std::string rawStr = arguments[1] + rawStr;
                std::string shaResult = sha1(rawStr);


            } else if(arguments[0] == "END"){
                std::string reply = "OK\n";
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == ""){

            } else if(arguments[0] == ""){
                
            } else if(arguments[0] == ""){
                
            } else if(arguments[0] == ""){
                
            } else if(arguments[0] == ""){
                
            }
            
        } else {
            ERR_print_errors_fp(stderr);
        }
        
    }

    // close the SSL connection and free resources
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(clientSocket);

    //Clean up SSL context
    SSL_CTX_free(sslContext);

    std::cout << "client is stopped" << std::endl;
    
    return 0;
}