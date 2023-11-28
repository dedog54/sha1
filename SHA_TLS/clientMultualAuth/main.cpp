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
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <sys/time.h>
#include <iomanip>

const char* SERVER_IP = "18.202.148.130";
const int SERVER_PORT = 3336;
// const char* SERVER_IP = "127.0.0.1";
// const int SERVER_PORT = 12345;

std::string sha1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

SHA_CTX g_ctxMainData;
pthread_cond_t g_condVar;
pthread_mutex_t g_mutexLock(PTHREAD_MUTEX_INITIALIZER);
bool g_bFound = false;
std::string result;

int get_count_of_cpu_cores() {
	return sysconf(_SC_NPROCESSORS_ONLN);
}

static void* Worker(void *param) {
	unsigned char data[64];
	SHA_CTX ctxLocalResult;
	unsigned char *pos_cur;

	struct timeval tv1;
	gettimeofday(&tv1, NULL);
	std::default_random_engine generator(tv1.tv_usec);
	std::uniform_int_distribution<int> distribution(33, 126);
	for (int i = 0; i < 55; i++)
		data[i] = distribution(generator);
	data[55] = 0x80;
	memset(data + 56, 0, 8);
	data[62] = 0x03;
	data[63] = 0xb8;

	while (true) {
		pos_cur = data;
		while (true) {
			if ((*pos_cur) == 126) {
				(*pos_cur) = 33;
				pos_cur++;
				continue;
			}
			(*pos_cur)++;
			memcpy(&ctxLocalResult, &g_ctxMainData, 32);
			SHA1_Transform(&ctxLocalResult, data);
			if (!ctxLocalResult.h0 && !(ctxLocalResult.h1 & 0x0fffffff)) {
				for (int i = 0; i < 55; i++ )
					std::cout << std::hex << int(data[i]) << " ";
				std::cout << std::endl;
				pthread_mutex_lock(&g_mutexLock);
				g_bFound = true;
				result = std::string(reinterpret_cast<char*>(data), sizeof(data));
				pthread_cond_signal(&g_condVar);
				pthread_mutex_unlock(&g_mutexLock);
				return 0;
			}
			break;
		}
	}

}

std::string calculateSuffix(const std::string & input){
    std::string auth = input;
	pthread_cond_init(&g_condVar, NULL);
	SHA1_Init(&g_ctxMainData);
	SHA1_Transform(&g_ctxMainData, (const unsigned char *)(auth.c_str()));

	for (int i = get_count_of_cpu_cores(); i; i--) {
		pthread_t tmpThreadID;
		pthread_create(&tmpThreadID, NULL, Worker, 0);
	}

	pthread_mutex_lock(&g_mutexLock);
	while (!g_bFound)
		pthread_cond_wait(&g_condVar, &g_mutexLock);
	pthread_mutex_unlock(&g_mutexLock);

	pthread_mutex_destroy(&g_mutexLock);
	pthread_cond_destroy(&g_condVar);
    std::string res = result;
    return res; 
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
    std::string authData;
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

            // std::cout << "argument[0] is: |" << arguments[0] << "||" << std::endl; 

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
                
                authData = arguments[1];
                std::string suffix = calculateSuffix(authData);
                std::string reply = suffix + "\n";
                // std::string reply = suffix;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "END"){
                std::string reply = "OK\n";
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "NAME"){
                std::string name = "Mofan Guo\n";
                std::string rawStr = authData + arguments[1];
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + name;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "MAILNUM"){
                std::string num = "1\n";
                std::string rawStr = authData + arguments[1];
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + num;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "MAIL1"){
                std::string email = "mofanguo54@gmail.com\n";
                std::string rawStr = authData + arguments[1];
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + email;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "MAIL2"){
                std::string email = "mofanguo54@gmail.com\n";
                std::string rawStr = authData + arguments[1];
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + email;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "SKYPE"){
                std::string skype = "mofanguo54@gmail.com\n";
                std::string rawStr = authData + arguments[1];
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + skype;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "BIRTHDATE"){
                std::string birthDate = "17.04.1998\n";
                std::string rawStr = authData + arguments[1];
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + birthDate;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "COUNTRY"){
                std::string country = "Germany\n";
                std::string rawStr = authData + arguments[1];
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + country;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "ADDRNUM"){
                std::string addrnum = "1\n";
                std::string rawStr = authData + arguments[1];
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + addrnum;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else if(arguments[0] == "ADDRLINE1"){
                std::string address = "64283 Darmstadt Neckarstrasse 15 zimmer 313\n";
                std::string rawStr = authData + arguments[1];
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + address;
                SSL_write(ssl, reply.c_str(), reply.length());
            } else {
                std::string nothing = "nothing\n";
                std::string rawStr = authData + arguments[1];
                std::string shaResult = sha1(rawStr);
                std::string reply = shaResult + " " + nothing;
                SSL_write(ssl, reply.c_str(), reply.length());
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