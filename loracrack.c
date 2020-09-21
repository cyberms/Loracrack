/* 
	Sipke Mellema
	AR '19
*/


#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include<stdlib.h>
#include<stdint.h>
#include <openssl/cmac.h>
#include <unistd.h>
#include "headers/loracrack.h"


#define MType_UP 0 // uplink
#define MType_DOWN 1 // downlink



int verbose = 0;

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

void build_decoding_table() {
 
    decoding_table = malloc(256);
 
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}

void base64_cleanup() {
    free(decoding_table);
}

char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {
    if (decoding_table == NULL) build_decoding_table();
 
    if (input_length % 4 != 0) return NULL;
 
    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;
 
    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;
	
    for (int i = 0, j = 0; i < input_length;) {
 
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
 
        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);
 
        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
	
	//fprintf(stderr,"Returning from B64 Decode\n");
    return decoded_data;
}

//function to convert ascii char[] to hex-string (char[])
char *string2hexString(unsigned char* input, size_t input_len){
    //fprintf(stderr,"string2hexString called\n");
 
	
	char *buffer = malloc(input_len*2 + 1);
	//insert NULL at the end of the output string
	buffer[input_len*2]='\0';

	//fprintf(stderr,"Input len: %ld\n", input_len);
	//fprintf(stderr,"Buffer len: %d\n", input_len*2 + 1);
    
	for(int i=0; i < input_len; i++){
		//printf(" i: %d:, %02X\n", i, input[i]);
		sprintf(&buffer[2*i], "%02X", input[i]);
    }

	return buffer;
}

// Variables shared among threads
volatile bool cracked = false;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Global variables
unsigned char *AppKey;
unsigned char *packet;
unsigned char MIC[4];
unsigned char *MIC_data;
unsigned short dev_nonce = 0;
bool dev_nonce_given = false;
unsigned int net_id = 19;

size_t MIC_data_len = 0;


int main (int argc, char **argv)
{
	char *AppKey_hex = NULL, *packet_b64= NULL, *net_id_hex= NULL;

	// Set number of threads
	// Intel(R) Core(TM) i5-7360U
	// See https://ark.intel.com/products/97535/Intel-Core-i5-7360U-Processor-4M-Cache-up-to-3-60-GHz-
	unsigned int n_threads = 1;

	// Set max App Nonce (<=16777216)
	unsigned int max_AppNonce = 16777216; 

	// Process args
	int c;
	while ((c = getopt (argc, argv, "v:p:k:t:m:n:i:")) != -1) 
	{
		switch (c)
		{
			case 'k':
				AppKey_hex = optarg;
				break;
			case 'p':
				packet_b64 = optarg;
				break;
			case 'v':
				verbose = atoi(optarg);
				break;
			case 't':
				n_threads = atoi(optarg);
				break;
			case 'm':
				max_AppNonce = atoi(optarg);
				break;
			case 'n':
				dev_nonce = atoi(optarg);
				dev_nonce_given = true;
				break;
			case 'i':
				net_id_hex = optarg;
				break;
		}
	}
	if (AppKey_hex == NULL || packet_b64 == NULL)
		error_die("Usage: \
			\n\t./loracrack -k <AppKey in hex> -p <B64 PHYPayload Data Packet> [-t <threads number> -m <max AppNonce> -n <DevNonce> -v <1,2 for verbose/ very verbose>]\
			\nExample: \
			\n\t./loracrack -k 88888888888888888888888888888888 -p QCopAiaAAAACkr0hb+tF4e89tcbVAUCD \n");

	// Convert B64 packet to bytes
	size_t b64_len= strlen(packet_b64);

	//printf("B64 packet is %s, len %ld\n", packet_b64, b64_len);


	size_t bytes_len;
	unsigned char *bytes = base64_decode(packet_b64, b64_len, &bytes_len);

	//fprintf(stderr,"After returned bytes_len: %ld\n", bytes_len );

	char *packet_hex= string2hexString(bytes, bytes_len);

	//printf("Hex str len %ld, Hex str %s\n", strlen(packet_hex), packet_hex);

	// Validate input - General
	validate_hex_input(AppKey_hex);
	validate_hex_input(packet_hex);
	
	// If net ID given, do some checks and get the value
	if (net_id_hex != NULL){
		validate_hex_input(net_id_hex);
		
		size_t net_id_len = strlen(net_id_hex) / 2;
		if ( net_id_len != 3)
			error_die("Net ID must be 3 bytes in hex format");

		// Convert hex to int 
		net_id = (int)strtol(net_id_hex, NULL, 16);
	}

	// Store data length
	size_t AppKey_len = strlen(AppKey_hex) / 2;
	size_t packet_len = strlen(packet_hex) / 2;

	// Validate input - Specific
	if (AppKey_len != 16)
		error_die("AppKey must be 16 bytes");
	if (packet_len <= 13)
		printf("Packet data too small");

	if (dev_nonce_given){
		if (dev_nonce < 0 || dev_nonce > 65535)
			error_die("Dev Nonce must be between 0 and 65,535");
	}

	// Convert to binary
	AppKey = hexstr_to_char(AppKey_hex);
	packet = hexstr_to_char(packet_hex);

	// Parse packet - MACHeader
	char MHDR = packet[0];
	int MType = bitExtracted(MHDR, 3, 6); // Byte 5-7

	if (MType < 2 || MType > 5)
		error_die("Packet not of type Data Up or Data Down");

	// Parse packet - Direction
	char Dir = 0;
	if (MType == 2 || MType == 4)
		Dir = MType_UP;
	if (MType == 3 || MType == 5)
		Dir = MType_DOWN;
	
	// Parse packet - Device address
	unsigned int DevAddr = 0;
	memcpy(&DevAddr, packet+1, 4);

	// Parse packet - FOptsLen
	int FCtrl = packet[5];
	int FOptsLen = bitExtracted(FCtrl, 4, 4);

	// Parse packet - FCnt
	short FCnt = 0;
	memcpy(&FCnt, packet+6, 2);

	// Skip FPort

	// Parse packet - FRMPayload
	size_t FRMPayload_index = 9 + FOptsLen;
	if (packet_len - 4 <= FRMPayload_index)
		error_die("No FRMPayload data");

	size_t FRMPayload_len = (packet_len - 4) - FRMPayload_index;
	unsigned char *FRMPayload = malloc(FRMPayload_len);
	memcpy(FRMPayload, packet+FRMPayload_index, FRMPayload_len);

	// Parse MIC data

	int msg_len = packet_len - 4;

	// Create B0
	char B0[16];
	B0[0] = 0x49;
	B0[1] = 0x00;
	B0[2] = 0x00;
	B0[3] = 0x00;
	B0[4] = 0x00;
	B0[5] = Dir;
	B0[6] = (DevAddr >> (8*0)) & 0xff;
	B0[7] = (DevAddr >> (8*1)) & 0xff;
	B0[8] = (DevAddr >> (8*2)) & 0xff;
	B0[9] = (DevAddr >> (8*3)) & 0xff;
	B0[10] = (FCnt >> (8*0)) & 0xff;
	B0[11] = (FCnt >> (8*1)) & 0xff;
	B0[12] = 0x00;
	B0[13] = 0x00;
	B0[14] = 0x00;
	B0[15] = msg_len;

	// Copy MIC data
	MIC_data_len = 16 + msg_len;
	MIC_data = malloc(MIC_data_len+1);
	memcpy(MIC_data, B0, 16);
	memcpy(MIC_data+16, packet, msg_len);

	// Copy MIC
	MIC[0] = *(packet + (packet_len - 4));
	MIC[1] = *(packet + (packet_len - 3));
	MIC[2] = *(packet + (packet_len - 2));
	MIC[3] = *(packet + (packet_len - 1));

	// Start cracking
	if (verbose) 
	{
		printf("------. L o R a C r a c k  ------\n");
		printf("\n\tBy Sipke Mellema '19\n\n");

		printf("Cracking with AppKey:\t");
		printBytes(AppKey, 16);

		printf("\nTrying to find MIC:\t");
		printBytes(MIC, 4);
	}

	// devide all possible nonces among threads
	unsigned int per_thread = max_AppNonce / n_threads;

	pthread_t tids[n_threads];

	if (verbose)
		printf("\n\nUsing %i threads, %i nonces per thread\n", n_threads, per_thread);

	unsigned long search_space = max_AppNonce * 0xffff;
	if (verbose)
		printf("max AppNonce = %u\nSearch space: %lu\n\n",max_AppNonce, search_space);

	// Create threads
	for (int i = 0; i < n_threads; i++) 
	{
		struct thread_args *thread_args = (struct thread_args *)malloc(sizeof(struct thread_args));

		thread_args->thread_ID = i;

		// Crack block size
		thread_args->AppNonce_start = i*per_thread;
		thread_args->AppNonce_end = (i*per_thread)+per_thread;

		// NetID zero for now
		thread_args->NetID_start = net_id;
		// thread_args->NetID_end = 0;

		// Create thread
		pthread_t tid;
		pthread_create(&tid, NULL, loracrack_thread, (void *)thread_args);
		tids[i] = tid;
	}

	// Wait for threads to finish
	for (int i = 0; i < n_threads; i++)
		pthread_join(tids[i], NULL);

	return 0;
}


// Thread for for trying to crack certain ranges
void *loracrack_thread(void *vargp) 
{ 

	// Cipher vars
	EVP_CIPHER_CTX ctx_aes128, ctx_aes128_buf;
	CMAC_CTX *ctx_aes128_cmac;

	// Output vars
	unsigned char NwkSKey[16];
	unsigned char cmac_result[16]; 
	size_t cmac_result_len;
	int outlen;

	unsigned int thread_ID = ((struct thread_args*)vargp)->thread_ID;

	// 3 byte integers
	unsigned int AppNonce_current = ((struct thread_args*)vargp)->AppNonce_start;
	unsigned int AppNonce_end = ((struct thread_args*)vargp)->AppNonce_end;

	// NetID not yet implemented
	unsigned int NetID_start = ((struct thread_args*)vargp)->NetID_start;
	// unsigned int NetID_end = ((struct thread_args*)vargp)->NetID_end;

	// 2 byte integer
	unsigned short DevNonce=0;

	if (verbose)
		printf("Thread %i cracking from AppNonce %i to %i\n", thread_ID, AppNonce_current, AppNonce_end);

	// Init ciphers
	EVP_CIPHER_CTX_init(&ctx_aes128);
	EVP_CIPHER_CTX_init(&ctx_aes128_buf);
	ctx_aes128_cmac = CMAC_CTX_new();

	// Session key generation buffer
	unsigned char message[16];
	memset(message, 0, 16);

	// NwkSKey = aes128_encrypt(AppKey, 0x01 | AppNonce | NetID | DevNonce | pad16)
	message[0] = 0x01;
	// https://stackoverflow.com/questions/7787423/c-get-nth-byte-of-integer
	message[1] = (AppNonce_current >> (8*0)) & 0xff;
	message[2] = (AppNonce_current >> (8*1)) & 0xff;
	message[3] = (AppNonce_current >> (8*2)) & 0xff;
	message[4] = (NetID_start >> (8*0)) & 0xff;
	message[5] = (NetID_start >> (8*1)) & 0xff;
	message[6] = (NetID_start >> (8*2)) & 0xff;
	message[7] = (DevNonce >> (8*0)) & 0xff; // Reversed?
	message[8] = (DevNonce >> (8*1)) & 0xff;

	EVP_EncryptInit_ex(&ctx_aes128_buf, EVP_aes_128_ecb(), NULL, AppKey, NULL);

	// AppNonce_end is exclusive
	while (AppNonce_current < AppNonce_end && !cracked) 
	{	
		
		if (dev_nonce_given)
			DevNonce = dev_nonce;
		else
			DevNonce = 0;

		if (verbose == 2)
			printf("Thread %i @ AppNonce %i\n", thread_ID, AppNonce_current);

		// Update AppNonce in message
		message[1] = (AppNonce_current >> (8*0)) & 0xff;
		message[2] = (AppNonce_current >> (8*1)) & 0xff;
		message[3] = (AppNonce_current >> (8*2)) & 0xff;

		while (DevNonce < 0xffff) 
		{
			// Update DevNonce in message
			message[7] = (DevNonce >> (8*0)) & 0xff; // Reversed?
			message[8] = (DevNonce >> (8*1)) & 0xff;

			// NwkSKey = aes128_ecb(AppKey, message)
			// copy init state instead of calling EVP_EncryptInit_ex every time
			memcpy(&ctx_aes128, &ctx_aes128_buf, sizeof(ctx_aes128_buf));
			EVP_EncryptUpdate(&ctx_aes128, NwkSKey, &outlen, message, 16);
			
			// MIC = aes128_cmac(NwkSKey, MIC_data)
			CMAC_Init(ctx_aes128_cmac, NwkSKey, 16, EVP_aes_128_cbc(), NULL);
			CMAC_Update(ctx_aes128_cmac, MIC_data, MIC_data_len);
			CMAC_Final(ctx_aes128_cmac, cmac_result, &cmac_result_len);

			// Check if MIC matches MIC from packet
			if (memcmp(cmac_result, MIC, 4) == 0) 
			{
				
				// cracked is used by multiple threads
				// pthread_mutex_lock(&mutex);
				// cracked = true;
				// pthread_mutex_unlock(&mutex);

				// Output cracked results
				if (verbose)
					printf("\nFound a pair of possible session keys\n");

				unsigned char AppSKey[16];
				
				message[0] = 0x02;
				EVP_EncryptInit_ex(&ctx_aes128, EVP_aes_128_ecb(), NULL, AppKey, NULL);
				EVP_EncryptUpdate(&ctx_aes128, AppSKey, &outlen, message, 16);

				if (verbose)
					printf("\nAppSKey,");
				printBytes(AppSKey, 16);
				
				printf(" ");

				if (verbose)
					printf("\nNwkSKey,");
				printBytes(NwkSKey, 16);
				
				if (verbose)
				{
					printf("\nAppNonce,%x (%d)\n", AppNonce_current, AppNonce_current);
					printf("DevNonce,%x (%d)\n", DevNonce, DevNonce);
				}

				// Clean aes data
				// EVP_CIPHER_CTX_cleanup(&ctx_aes128);
				// CMAC_CTX_free(ctx_aes128_cmac);

				//break;

				message[0] = 0x01;
			}
			if (dev_nonce_given){
				break;
			}
			else{
				DevNonce += 1;
			}

		}
		AppNonce_current += 1;
	}

    return NULL; 
} 
