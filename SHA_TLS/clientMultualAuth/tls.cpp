#include "tls.h"

TLSConnection::TLSConnection(const char* SERVER_IP, const int SERVER_PORT, const char* ca_cert, 
            const char* server_cert, const char* server_key):SERVER_IP(SERVER_IP), SERVER_PORT(SERVER_PORT),ca_cert(ca_cert),
            server_cert(server_cert),server_key(server_key){}

void TLSConnection::initialConnection(){
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    std::cout << "Client is working" << std::endl;
    
    //Create an SSL context
    sslContext = SSL_CTX_new(TLS_client_method());
    if(!sslContext) {
        ERR_print_errors_fp(stderr);
        return;
    }

    // Load CA certificate of the server for verification
    if (SSL_CTX_load_verify_locations(sslContext, ca_cert, NULL) == 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    // Load client certificate and private key
    if (SSL_CTX_use_certificate_file(sslContext, server_cert, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(sslContext, server_key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    //Create a socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(clientSocket == -1){
        perror("Error creating socket");
        return;
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
        return;
    }

    
    //Create an SSL object and associate it with the socket
    ssl = SSL_new(sslContext);
    SSL_set_fd(ssl, clientSocket);

    if(SSL_connect(ssl) <= 0){
        ERR_print_errors_fp(stderr);
        close(clientSocket);
        return;
    }
}

void TLSConnection::handShakeWithServer(){
    while (true) {
        

        //Receive and print response from the server
        char buffer[1024];
        int bytesRead = SSL_read(ssl, buffer, sizeof(buffer));
        if(bytesRead > 0){
            buffer[bytesRead] = '\0';
            std::cout << "Received from server: " << buffer << std::endl;

            //split the argument into arguments
            std::string receivedData(buffer);
            std::stringstream ss(receivedData);
            std::string argument;
            std::vector<std::string> arguments;

            while(std::getline(ss, argument, ' ')){
                arguments.push_back(argument);
            }

            //deal with arguments
            if(arguments[0] == "HELO\n"){
                std::string reply = "EHLO\n";
                
                SSL_write(ssl, reply.c_str(), reply.length());
                
            } else if(arguments[0] == "ERROR"){
                std::string error_str = "";
                for(int i = 1; i < arguments.size(); i++){
                    error_str += " ";
                    error_str += arguments[i];
                }
                std::cout << "ERROR: " << error_str << std::endl;
            } else if(arguments[0] == "POW"){
                
                authData = arguments[1];
                std::string suffix = calculateSuffix(authData);
                std::string reply = suffix + "\n";
                std::cout << "Sending suffix: " << reply << std::endl;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "END"){
                std::string reply = "OK\n";
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "NAME"){
                std::string name = "Mofan Guo\n";
                std::string rawStr = authData + arguments[1].substr(0, arguments[1].size() - 1);
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + name;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "MAILNUM"){
                std::string num = "1\n";
                std::string rawStr = authData + arguments[1].substr(0, arguments[1].size() - 1);
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + num;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "MAIL1"){
                std::string email = "mofanguo54@gmail.com\n";
                std::string rawStr = authData + arguments[1].substr(0, arguments[1].size() - 1);
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + email;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "MAIL2"){
                std::string email = "mofanguo54@gmail.com\n";
                std::string rawStr = authData + arguments[1].substr(0, arguments[1].size() - 1);
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + email;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "SKYPE"){
                std::string skype = "mofanguo54@gmail.com\n";
                std::string rawStr = authData + arguments[1].substr(0, arguments[1].size() - 1);
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + skype;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "BIRTHDATE"){
                std::string birthDate = "17.04.1998\n";
                std::string rawStr = authData + arguments[1].substr(0, arguments[1].size() - 1);
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + birthDate;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "COUNTRY"){
                std::string country = "Germany\n";
                std::string rawStr = authData + arguments[1].substr(0, arguments[1].size() - 1);
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + country;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "ADDRNUM"){
                std::string addrnum = "1\n";
                std::string rawStr = authData + arguments[1].substr(0, arguments[1].size() - 1);
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + addrnum;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "ADDRLINE1"){
                std::string address = "64283 Darmstadt Neckarstrasse 15 zimmer 313\n";
                std::string rawStr = authData + arguments[1].substr(0, arguments[1].size() - 1);
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + address;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else {
                std::string nothing = "nothing\n";
                std::string rawStr = authData + arguments[1].substr(0, arguments[1].size() - 1);
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + nothing;
                SSL_write(ssl, reply.c_str(), reply.length());
            }
            
        } else {
            ERR_print_errors_fp(stderr);
        }
        
    }
}

void TLSConnection::closeConnection(){
     // close the SSL connection and free resources
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(clientSocket);

    //Clean up SSL context
    SSL_CTX_free(sslContext);

    std::cout << "Client is stopped" << std::endl;
}

