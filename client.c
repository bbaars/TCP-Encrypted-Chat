/*
* @authors: Brandon Baars, Mike Ford, Isaac Benson
* @date: 03/15/2018
* @description: CIS 457 Project 3: TCP Encrytped Chat Client
*
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/lhash.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out);
void handleErrors(void);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext);

int main(int argc, char** argv)
{
	//set up library
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

	bool run = true;
	int sockfd = socket(AF_INET,SOCK_STREAM,0);
	int port = 0;
	int i;
	unsigned char key[32];
	  unsigned char iv[16];
	EVP_PKEY *pubkey;
	fd_set sockets;
	FD_ZERO(&sockets);


	FILE* pubf = fopen("RSApub.pem","rb");
  pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);

	//key with 32 bytes
	RAND_bytes(key,32);

//printf("Client Key\n");
//BIO_dump_fp (stdout, (const char *)key, 32);

	unsigned char encrypted_key[256]={0};
	//using puclic key to encrypt symetric key
	int encryptedkey_len = rsa_encrypt(key, 32, pubkey, encrypted_key);

	//printf("Key sent:\n");
	//for(i=0; i<32; i++)
		//							printf("%c\n",key[i]);

	/*Attempt to set up Socket*/
	if(sockfd<0)
	{
		printf("There was an error creating the socket\n");
		return 1;
	}

	printf("--------------Welcome to the TCP Encrypted Chat Client--------------"
	"\nCOMMAND:                    DESCRIPTION:"
	"\n-m [client_id] [message]    send a message to a client"
	"\n-b [message]                send a broadcast message"
	"\n-l                          retrieve a list of all clients"
	"\n-k [client_id]              kick off another client (admin req.)"
	"\n-q                          Quit"
	"\n--------------------------------------------------------------------\n"
);

/*Take input for port number*/
printf("\nEnter in a port number:   ");
scanf("%d", &port);

/*Remove newline character that results from calling scanf()*/
getchar();

/*Set up connection to server*/
struct sockaddr_in serveraddr;
serveraddr.sin_family=AF_INET;
serveraddr.sin_port=htons(port);
serveraddr.sin_addr.s_addr=inet_addr("127.0.0.1");

/*Attempt to connect to server*/
int e = connect(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
if(e<0)
{
	printf("There was an error connecting\n");
	return 1;
}

send(sockfd,encrypted_key,encryptedkey_len,0);

/*Prompt to enter a command*/
printf("Enter a command: ");
fflush(stdout);

/*Set stdin and socket select bits*/
FD_SET (0, &sockets);
FD_SET (sockfd, &sockets);
while (run)
{

	fd_set tmp_set = sockets;
	select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);

	/*Iterate through select bits*/
	for (i = 0; i < FD_SETSIZE; i++)
	{
		if(FD_ISSET(i, &tmp_set))
		{
			/*If user is typing into the console*/
			if (i == 0)
			{
				char line[5000];
				unsigned char ciphertext[5000];
				unsigned char newLine[5000];
				unsigned char decryptedtext[5000];
				int decryptedtext_len, ciphertext_len;

				printf("Enter a command: ");

				//make initialization vector (every mesage)
				RAND_pseudo_bytes(iv,16);

				fgets(line, 5000, stdin);


				//encrypt message
			  ciphertext_len = encrypt (line, strlen ((char *)line), key, iv,
			                            ciphertext);

				memcpy(&newLine[0],&ciphertext_len,1);
				memcpy(&newLine[1],&iv[0],16);
					memcpy(&newLine[17],&ciphertext[0],ciphertext_len);




				send(sockfd,newLine,18+ciphertext_len,0);
			}

			/*If the server is sending something to the client*/
			else if (i == sockfd)
			{

        unsigned char line[5000];
        int encryptedTextLength;
        unsigned char receivedIV[16];
        unsigned char encryptedText[5000];
        unsigned char decryptedtext[5000];
        int decryptedtext_len;
        int rec = recv(sockfd, line, 5000, 0);

        if(rec > 1) {
                        encryptedTextLength = (int)line[0];
//printf("Length received: %d\n",encryptedTextLength );
                        memcpy(&receivedIV[0], &line[1],16);
  //                      printf("IV is:\n");
    //                    BIO_dump_fp (stdout, (const char *)receivedIV, 16);
                        memcpy(&encryptedText[0],&line[17],encryptedTextLength);
      //                  printf("Ciphertext is:\n");
        //                BIO_dump_fp (stdout, (const char *)encryptedText, encryptedTextLength);

                        decryptedtext_len = decrypt(encryptedText, encryptedTextLength, key, receivedIV,
                                                                                decryptedtext);

                        decryptedtext[decryptedtext_len] = '\0';

                        EVP_cleanup();
                        ERR_free_strings();
                      }

				/*If quit message was received, exit*/
				if (strstr((char*)decryptedtext, "disconnected from server") != NULL)
				{
					run = false;
					printf("Disconnected from servers\n"); //Newline
					break;
				}
				printf("\nGot from server: %s\n",decryptedtext);
				fflush(stdout);
			}
		}
	}
}

close(sockfd);
return 0;

}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}
//encrypt and decrypt with  public/private key
int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}
//encrypt and decrypt with  semetric key
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}
