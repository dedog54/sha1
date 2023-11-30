//============================================================================
// Name        : main.cpp
// Author      : dedog54
// Version     :
// Copyright   : 
// Description : 
//============================================================================
#include <iostream>
#include "tls.h"


int main(){
    //Set the info of the server
    const char* SERVER_IP = "18.202.148.130";
    const int SERVER_PORT = 3336;
    // const char* SERVER_IP = "127.0.0.1";
    // const int SERVER_PORT = 12345;
    const char* ca_cert = "ca.crt";
    const char* server_cert = "client.crt";
    const char* server_key = "client.key";
    TLSConnection* tls = new TLSConnection(SERVER_IP, SERVER_PORT, ca_cert, server_cert, server_key);
    tls->initialConnection();
    tls->handShakeWithServer();
    tls->closeConnection();
    return 0;
}

