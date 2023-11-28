//============================================================================
// Name        : BruteForceSHA1CPU.cpp
// Author      : Maxx
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <random>
#include <unistd.h>
#include <sys/time.h>
#include <string>
using namespace std;

//"vJKwwHCzrRjMSPoDXLPUkUMHoKvxlHrUADyUNBSXalLlHLcYPKRTRzoALeYowVsO";
SHA_CTX g_ctxMainData;

pthread_cond_t g_condVar;
pthread_mutex_t g_mutexLock(PTHREAD_MUTEX_INITIALIZER);
bool g_bFound = false;

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
			if (!ctxLocalResult.h0 && !(ctxLocalResult.h1 & 0x00000fff)) {
				for (int i = 0; i < 55; i++ )
					cout << hex << int(data[i]) << " ";
				cout << endl;
				pthread_mutex_lock(&g_mutexLock);
				g_bFound = true;
				pthread_cond_signal(&g_condVar);
				pthread_mutex_unlock(&g_mutexLock);
				return 0;
			}
			break;
		}
	}

}

int main() {
    std::string auth = "vJKwwHCzrRjMSPoDXLPUkUMHoKvxlHrUADyUNBSXalLlHLcYPKRTRzoALeYowVsO";
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

	return 0;
}