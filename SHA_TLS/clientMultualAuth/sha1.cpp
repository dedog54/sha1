#include "sha1.h"
#include <sstream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <stdio.h>
#include <random>
#include <iostream>
#include <sys/time.h>

 
/* Help macros */
#define SHA1_ROL(value, bits) (((value) << (bits)) | (((value) & 0xffffffff) >> (32 - (bits))))
#define SHA1_BLK(i) (block[i&15] = SHA1_ROL(block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i&15],1))
 
/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define SHA1_R0(v,w,x,y,z,i) z += ((w&(x^y))^y)     + block[i]    + 0x5a827999 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R1(v,w,x,y,z,i) z += ((w&(x^y))^y)     + SHA1_BLK(i) + 0x5a827999 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R2(v,w,x,y,z,i) z += (w^x^y)           + SHA1_BLK(i) + 0x6ed9eba1 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R3(v,w,x,y,z,i) z += (((w|x)&y)|(w&x)) + SHA1_BLK(i) + 0x8f1bbcdc + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R4(v,w,x,y,z,i) z += (w^x^y)           + SHA1_BLK(i) + 0xca62c1d6 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);

// SHA_CTX g_ctxMainData;
pthread_cond_t g_condVar;
pthread_mutex_t g_mutexLock(PTHREAD_MUTEX_INITIALIZER);
bool g_bFound = false;
std::string result;
SHA1 globalChecksum;
 
SHA1::SHA1()
{
    reset();
}
 
 
void SHA1::update(const std::string &s)
{
    std::istringstream is(s);
    update(is);
}
 
 
void SHA1::update(std::istream &is)
{
    // static const unsigned int BLOCK_INTS = 16;  /* number of 32bit integers per SHA1 block */
    // static const unsigned int BLOCK_BYTES = BLOCK_INTS * 4;
    std::string rest_of_buffer;
    // eading data from an input stream (is) into a buffer (rest_of_buffer)
    // at begining the buffer size is 0
    //so it actually read 64 bytes into rest of buffer
    read(is, rest_of_buffer, BLOCK_BYTES - buffer.size());
    buffer += rest_of_buffer;
 
    while (is)
    {
        
        uint32 block[BLOCK_INTS];
        buffer_to_block(buffer, block);
        //the transform function works on the block
        transform(block);
        //here it will replace buffer with nuew one
        read(is, buffer, BLOCK_BYTES);
    }
}
 
 
/*
 * Add padding and return the message digest.
 */
 
std::string SHA1::final()
{
    /* Total number of hashed bits */
    // for input size of 64bytes + 55 bytes
    // transform is now executed only by one time
    //total bits is:(1*64 + 55) * 8 
    uint64 total_bits = (transforms*BLOCK_BYTES + buffer.size()) * 8;
 
    /* Padding */
    //now the buffer size is 56
    buffer += 0x80;
    unsigned int orig_size = buffer.size();
    //padding buffer until size 64
    while (buffer.size() < BLOCK_BYTES)
    {
        buffer += (char)0x00;
    }
 
    uint32 block[BLOCK_INTS];
    buffer_to_block(buffer, block);
    //origin size is 56
    //This means the buffer size greater than 56
    if (orig_size > BLOCK_BYTES - 8)
    {
        //if so do the transform and update the block
        transform(block);
        for (unsigned int i = 0; i < BLOCK_INTS - 2; i++)
        {
            block[i] = 0;
        }
    }
    //anyway, if origin size is 56, it will only do two transforms
 
    /* Append total_bits, split this uint64 into two uint32 */
    // append total bits at block[15] and block[14]
    block[BLOCK_INTS - 1] = total_bits;
    block[BLOCK_INTS - 2] = (total_bits >> 32);
    transform(block);
 
    /* Hex std::string */
    std::ostringstream result;
    for (unsigned int i = 0; i < DIGEST_INTS; i++)
    {
        result << std::hex << std::setfill('0') << std::setw(8);
        result << (digest[i] & 0xffffffff);
    }
 
    /* Reset for next run */
    reset();
 
    return result.str();
}
 
 
std::string SHA1::from_file(const std::string &filename)
{
    std::ifstream stream(filename.c_str(), std::ios::binary);
    SHA1 checksum;
    checksum.update(stream);
    return checksum.final();
}
 
 
void SHA1::reset()
{
    /* SHA1 initialization constants */
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;
 
    /* Reset counters */
    transforms = 0;
    buffer = "";
}
 
 
/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */
 
void SHA1::transform(uint32 block[BLOCK_BYTES])
{
    /* Copy digest[] to working vars */
    uint32 a = digest[0];
    uint32 b = digest[1];
    uint32 c = digest[2];
    uint32 d = digest[3];
    uint32 e = digest[4];
 
 
    /* 4 rounds of 20 operations each. Loop unrolled. */
    SHA1_R0(a,b,c,d,e, 0);
    SHA1_R0(e,a,b,c,d, 1);
    SHA1_R0(d,e,a,b,c, 2);
    SHA1_R0(c,d,e,a,b, 3);
    SHA1_R0(b,c,d,e,a, 4);
    SHA1_R0(a,b,c,d,e, 5);
    SHA1_R0(e,a,b,c,d, 6);
    SHA1_R0(d,e,a,b,c, 7);
    SHA1_R0(c,d,e,a,b, 8);
    SHA1_R0(b,c,d,e,a, 9);
    SHA1_R0(a,b,c,d,e,10);
    SHA1_R0(e,a,b,c,d,11);
    SHA1_R0(d,e,a,b,c,12);
    SHA1_R0(c,d,e,a,b,13);
    SHA1_R0(b,c,d,e,a,14);
    SHA1_R0(a,b,c,d,e,15);
    SHA1_R1(e,a,b,c,d,16);
    SHA1_R1(d,e,a,b,c,17);
    SHA1_R1(c,d,e,a,b,18);
    SHA1_R1(b,c,d,e,a,19);
    SHA1_R2(a,b,c,d,e,20);
    SHA1_R2(e,a,b,c,d,21);
    SHA1_R2(d,e,a,b,c,22);
    SHA1_R2(c,d,e,a,b,23);
    SHA1_R2(b,c,d,e,a,24);
    SHA1_R2(a,b,c,d,e,25);
    SHA1_R2(e,a,b,c,d,26);
    SHA1_R2(d,e,a,b,c,27);
    SHA1_R2(c,d,e,a,b,28);
    SHA1_R2(b,c,d,e,a,29);
    SHA1_R2(a,b,c,d,e,30);
    SHA1_R2(e,a,b,c,d,31);
    SHA1_R2(d,e,a,b,c,32);
    SHA1_R2(c,d,e,a,b,33);
    SHA1_R2(b,c,d,e,a,34);
    SHA1_R2(a,b,c,d,e,35);
    SHA1_R2(e,a,b,c,d,36);
    SHA1_R2(d,e,a,b,c,37);
    SHA1_R2(c,d,e,a,b,38);
    SHA1_R2(b,c,d,e,a,39);
    SHA1_R3(a,b,c,d,e,40);
    SHA1_R3(e,a,b,c,d,41);
    SHA1_R3(d,e,a,b,c,42);
    SHA1_R3(c,d,e,a,b,43);
    SHA1_R3(b,c,d,e,a,44);
    SHA1_R3(a,b,c,d,e,45);
    SHA1_R3(e,a,b,c,d,46);
    SHA1_R3(d,e,a,b,c,47);
    SHA1_R3(c,d,e,a,b,48);
    SHA1_R3(b,c,d,e,a,49);
    SHA1_R3(a,b,c,d,e,50);
    SHA1_R3(e,a,b,c,d,51);
    SHA1_R3(d,e,a,b,c,52);
    SHA1_R3(c,d,e,a,b,53);
    SHA1_R3(b,c,d,e,a,54);
    SHA1_R3(a,b,c,d,e,55);
    SHA1_R3(e,a,b,c,d,56);
    SHA1_R3(d,e,a,b,c,57);
    SHA1_R3(c,d,e,a,b,58);
    SHA1_R3(b,c,d,e,a,59);
    SHA1_R4(a,b,c,d,e,60);
    SHA1_R4(e,a,b,c,d,61);
    SHA1_R4(d,e,a,b,c,62);
    SHA1_R4(c,d,e,a,b,63);
    SHA1_R4(b,c,d,e,a,64);
    SHA1_R4(a,b,c,d,e,65);
    SHA1_R4(e,a,b,c,d,66);
    SHA1_R4(d,e,a,b,c,67);
    SHA1_R4(c,d,e,a,b,68);
    SHA1_R4(b,c,d,e,a,69);
    SHA1_R4(a,b,c,d,e,70);
    SHA1_R4(e,a,b,c,d,71);
    SHA1_R4(d,e,a,b,c,72);
    SHA1_R4(c,d,e,a,b,73);
    SHA1_R4(b,c,d,e,a,74);
    SHA1_R4(a,b,c,d,e,75);
    SHA1_R4(e,a,b,c,d,76);
    SHA1_R4(d,e,a,b,c,77);
    SHA1_R4(c,d,e,a,b,78);
    SHA1_R4(b,c,d,e,a,79);
 
    /* Add the working vars back into digest[] */
    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;
 
    /* Count the number of transformations */
    transforms++;
}
 
 
void SHA1::buffer_to_block(const std::string &buffer, uint32 block[BLOCK_BYTES])
{
    /* Convert the std::string (byte buffer) to a uint32 array (MSB) */
    for (unsigned int i = 0; i < BLOCK_INTS; i++)
    {
        block[i] = (buffer[4*i+3] & 0xff)
                   | (buffer[4*i+2] & 0xff)<<8
                   | (buffer[4*i+1] & 0xff)<<16
                   | (buffer[4*i+0] & 0xff)<<24;
    }
}
 
 
void SHA1::read(std::istream &is, std::string &s, int max)
{
    char sbuf[max];
    is.read(sbuf, max);
    s.assign(sbuf, is.gcount());
}

void SHA1::copy_digest(uint32 *newDigest){
    this->digest[0] = newDigest[0];
    this->digest[1] = newDigest[1];
    this->digest[2] = newDigest[2];
    this->digest[3] = newDigest[3];
    this->digest[4] = newDigest[4];
}
 
 
std::string sha1(const std::string &string)
{
    std::cout << "the sha1 string is: |" << string << "|"<< std::endl;
    SHA1 checksum;
    checksum.update(string);
    std::string finalCheckSum = checksum.final();
    std::cout << "The final checksum is: " << finalCheckSum << std::endl;
    return finalCheckSum;
}

static void* Worker(void *param) {
	unsigned char data[64];
	struct timeval tv1;
	gettimeofday(&tv1, NULL);
	std::default_random_engine generator(tv1.tv_usec);
	std::uniform_int_distribution<int> distribution(33, 126);
	for (int i = 0; i < 55; i++)
		data[i] = distribution(generator);
    
    std::string secondBuffer = std::string(reinterpret_cast<char*>(data), 55);
    secondBuffer += 0x80;
    while (secondBuffer.size() < 64)
    {
        secondBuffer += (char)0x00;
    }
    secondBuffer[62] = static_cast<char>(0x03);
	secondBuffer[63] = static_cast<char>(0xb8);

	while (true) {
		int index = 0;
		while (true) {
			if (secondBuffer[index] == '~') {
				secondBuffer[index] = '!';
				index++;
				continue;
			}
            secondBuffer[index] = static_cast<char>(secondBuffer[index] + 1);
			// memcpy(&ctxLocalResult, &g_ctxMainData, 32);
            SHA1 currentChecksum;

            // currentChecksum.digest = globalChecksum.digest;
            currentChecksum.copy_digest(globalChecksum.digest);
            //at this we should copy a new checksum
			// SHA1_Transform(&ctxLocalResult, data);
            unsigned long int block[16];
            currentChecksum.buffer_to_block(secondBuffer, block);
            currentChecksum.transform(block);
			if (!(currentChecksum.digest[0] & 0xffffffff) && !(currentChecksum.digest[1] & 0xf0000000)) {
				pthread_mutex_lock(&g_mutexLock);
				g_bFound = true;
				result = secondBuffer.substr(0, 55);
				pthread_cond_signal(&g_condVar);
				pthread_mutex_unlock(&g_mutexLock);
				return 0;
			}
			break;
		}
	}

}

/*
 * calculate a suffix that input (suffix + auth) only involves in two transform
 */
std::string calculateSuffix(const std::string & input)
{
    std::string auth = input;
	pthread_cond_init(&g_condVar, NULL);
	// SHA1_Init(&g_ctxMainData);
    unsigned long int block[16];
    globalChecksum.buffer_to_block(input, block);
    globalChecksum.transform(block);
    
	// SHA1_Transform(&g_ctxMainData, (const unsigned char *)(auth.c_str()));
    int cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    

	for (int i = cpu_count; i; i--) {
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