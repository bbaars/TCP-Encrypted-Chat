/*
 * @authors: Brandon Baars, Mike Ford, Isaac Benson
 * @date: 03/15/2018
 * @description: CIS 457 Project 3: TCP Encrytped Chat Server
 *
 */

/* ===============================================================
 * HOW TO COMPILE
 * g++ server.cpp -lssl -lcrypto -pthread -o server
 * ===============================================================*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <map>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <arpa/inet.h>
#include <sstream>
#include <openssl/lhash.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>


// PTHREADS SSL_CTX
#ifdef LINUX
# include <typedefs.h>
#endif
#ifdef PTHREADS
# include <pthread.h>
#endif

#ifdef OPENSSL_SYS_NETWARE
# define TEST_SERVER_CERT "/openssl/apps/server.pem"
# define TEST_CLIENT_CERT "/openssl/apps/client.pem"
#else
# define TEST_SERVER_CERT "../../apps/server.pem"
# define TEST_CLIENT_CERT "../../apps/client.pem"
#endif

#define MAX_THREAD_NUMBER       100

BIO *bio_err = NULL;
BIO *bio_stdout = NULL;

static char *cipher = NULL;
int verbose = 0;

int thread_number = 10;
int number_of_loops = 10;
int reconnect = 0;
int cache_stats = 0;
unsigned char iv[16];

EVP_PKEY *privkey;

// FUNCTION DECLARATIONS
void parse_message(struct client_info & client);
void * handle_receive(void * client_arg);
void send_list(struct client_info client);
void terminate_user(struct client_info client);
std::string parse_id(std::string message);
void broadcast(struct client_info client);

// PHTREADS SSL_CTX
int verify_callback(int ok, X509_STORE_CTX *xs);
void thread_setup(void);
void thread_cleanup(void);
void do_threads(SSL_CTX *s_ctx, SSL_CTX *c_ctx);
void pthreads_locking_callback(int mode, int type, const char *file, int line);
void pthreads_thread_id(CRYPTO_THREADID *tid);
int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out);
void handleErrors(void);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext);

// Struct that handles our clients request.
struct client_info {

								int from_socket; // socket the request was from
								uint32_t ipaddr; // ip address of the client
								std::vector<int> to_socket; // vector to hold the sockets to send to (broadcast or 1)
								std::string message; // message the client wants to send
								bool is_admin; // whether or not the client has admin access
								pthread_t id; // thread id that this client is attached to
								std::string username; // the username of the client (used to map itself to the map?)
								unsigned char symmetric_key[32];

};

// list of all the connected clients
std::map<std::string, struct client_info> connected_clients;

//Global password
std::string PASSWORD = "password\n";

/*
 *	Handle the connection received with the client
 */
void * handle_receive(void * client_arg) {

								struct client_info client = *(struct client_info*) client_arg;
								struct in_addr ipaddr;
								int i;
								ipaddr.s_addr = client.ipaddr;

								std::cout << "Received client: " << client.from_socket << " from IP Addr: "
																		<< inet_ntoa(ipaddr) << std::endl;

								unsigned char receivedKey[5000];
								int rec = recv(client.from_socket, receivedKey, 5000, 0);


								unsigned char decrypted_key[32];
								//use privat key to decrypt semetric key

								int decryptedkey_len = rsa_decrypt(receivedKey, 256, privkey, client.symmetric_key);


								for (std::map<std::string, struct client_info>::iterator it=connected_clients.begin(); it!=connected_clients.end(); ++it)
								{
																if (client.username == it->second.username)
																{
																								memcpy(it->second.symmetric_key, client.symmetric_key, 32);
																}
								}
								//	std::cout << "Client " << client.from_socket << "has key: "<< '\n';
								//	BIO_dump_fp (stdout, (const char *)client.symmetric_key, 32);

								// while there is still an active connection with the client
								bool is_running = true;

								client.id = pthread_self();

								while(is_running) {

																unsigned char line[5000]=" ";
																int encryptedTextLength;
																unsigned char receivedIV[16]=" ";
																unsigned char encryptedText[5000]=" ";
																unsigned char decryptedtext[5000]=" ";
																char finalString[5000]=" ";
																int decryptedtext_len;
																int rec = recv(client.from_socket, line, 5000, 0);

																if(rec > 1) {
																								encryptedTextLength = (int)line[0];
																								memcpy(&receivedIV[0], &line[1],16);
																								memcpy(&encryptedText[0],&line[17],encryptedTextLength);

																								decryptedtext_len = decrypt(encryptedText, encryptedTextLength, client.symmetric_key, receivedIV,
																																																				decryptedtext);

																								decryptedtext[decryptedtext_len] = '\0';
																								memcpy(&finalString,&decryptedtext[0],decryptedtext_len);
																								printf("Decrypted text is:\n");
																								printf("%s\n", decryptedtext);
																								EVP_cleanup();
																								ERR_free_strings();
																								//std::cout << "Final string" <<finalString<< '\n';
																								std::string str_line( finalString );

																								client.message = str_line;
																								//std::cout << "Stored client message:" << client.message<<'\n';
																								//if there was a message received with more than a command (i.e 2 characters -L)
																								if (rec >= 2) {
																																parse_message(client);
																								}
																								client.message.clear();
																								//	std::cout << "Stored client message after clear:" << client.message<<'\n';
																}

								}

								return NULL;
}


void parse_message(struct client_info & client) {

								// There was an argument given
								if(client.message.find("-") == 0) {

																// make sure we don't get index out of bounds
																if (client.message.length() >= 2) {

																								// get the command issued by the client
																								char command = client.message.at(1);
																								std::string id;

																								unsigned char error[] = "Sorry, there was an error";
																								unsigned char passwordError[] = "Incorrect Password.";
																								unsigned char notAnAdmin[] = "You are not an admin.";
																								unsigned char cantKickAdmin[] = "You cannot kick another admin.";
																								unsigned char nowAnAdmin[] = "You are now an admin.";

																								unsigned char ciphertext[5000];
																								unsigned char newLine[5000];
																								unsigned char decryptedtext[5000];
																								int decryptedtext_len, ciphertext_len=0;
																								unsigned char message[5000];

																								switch(command) {

																								case 'L':
																								case 'l':
																																send_list(client);
																																break;
																								case 'M':
																								case 'm':
																																// parse for recipient id
																																// send client message
																																// TODO: Reformat string to include who it's from
																																id = parse_id(client.message);
																																if (!id.empty() && client.message.length() > 5) {
																																								// send to other client the message - the command and id

																																								memcpy(message, client.message.substr(client.message.find(id) + 1).c_str(),strlen(client.message.substr(client.message.find(id) + 1).c_str())+1);

																																								RAND_pseudo_bytes(iv,16);
																																								//encrypt message
																																								ciphertext_len = encrypt(message, strlen((char *)message), connected_clients[id].symmetric_key, iv,ciphertext);

																																								memcpy(&newLine[0],&ciphertext_len,1);
																																								memcpy(&newLine[1],&iv[0],16);
																																								memcpy(&newLine[17],&ciphertext[0],ciphertext_len);


																																								send(connected_clients[id].from_socket,newLine,18+ciphertext_len, 0);
																																} else {
																																								RAND_pseudo_bytes(iv,16);
																																								//encrypt message
																																								ciphertext_len = encrypt(error, strlen((char *)error), client.symmetric_key, iv,ciphertext);

																																								memcpy(&newLine[0],&ciphertext_len,1);
																																								memcpy(&newLine[1],&iv[0],16);
																																								memcpy(&newLine[17],&ciphertext[0],ciphertext_len);


																																								send(client.from_socket,newLine,18+ciphertext_len, 0);
																																								// Send messge back to client saying can't send message to self

																																}

																																break;
																								case 'B':
																								case 'b':
																																// broadcast messagee
																																broadcast(client);
																																break;
																								case 'k':
																								case 'K':
																																// check is the user is an admin, and the person they want to kick is NOTs
																																if (client.is_admin) {
																																								if(!connected_clients[parse_id(client.message)].is_admin) {
																																																terminate_user(connected_clients[parse_id(client.message)]);
																																								} else {

																																																RAND_pseudo_bytes(iv,16);
																																																//encrypt message
																																																ciphertext_len = encrypt(cantKickAdmin, strlen((char *)cantKickAdmin), client.symmetric_key, iv,ciphertext);

																																																memcpy(&newLine[0],&ciphertext_len,1);
																																																memcpy(&newLine[1],&iv[0],16);
																																																memcpy(&newLine[17],&ciphertext[0],ciphertext_len);


																																																send(client.from_socket,newLine,18+ciphertext_len, 0);

																																								}
																																} else{
																																								RAND_pseudo_bytes(iv,16);
																																								//encrypt message
																																								ciphertext_len = encrypt(notAnAdmin, strlen((char *)notAnAdmin), client.symmetric_key, iv,ciphertext);

																																								memcpy(&newLine[0],&ciphertext_len,1);
																																								memcpy(&newLine[1],&iv[0],16);
																																								memcpy(&newLine[17],&ciphertext[0],ciphertext_len);


																																								send(client.from_socket,newLine,18+ciphertext_len, 0);
																																}

																																break;
																								case 'q':
																								case 'Q':
																																// close the thread and remove client from active list
																																terminate_user(client);
																																break;

																								case 'a':
																								case 'A':
																																//std::cout << "Pass:" << client.message.substr(client.message.find("-")+3)<<'\n';
																																if(client.message.substr(client.message.find("-")+3).compare(PASSWORD) == 0) {
																																								client.is_admin = true;
																																								for (std::map<std::string, struct client_info>::iterator it=connected_clients.begin(); it!=connected_clients.end(); ++it)
																																								{
																																																if (client.username == it->second.username)
																																																{
																																																								it->second.is_admin = true;
																																																}
																																								}

																																								RAND_pseudo_bytes(iv,16);
																																								//encrypt message
																																								ciphertext_len = encrypt(nowAnAdmin, strlen((char *)nowAnAdmin), client.symmetric_key, iv,ciphertext);

																																								memcpy(&newLine[0],&ciphertext_len,1);
																																								memcpy(&newLine[1],&iv[0],16);
																																								memcpy(&newLine[17],&ciphertext[0],ciphertext_len);


																																								send(client.from_socket,newLine,18+ciphertext_len, 0);
																																} else{
																																								RAND_pseudo_bytes(iv,16);
																																								//encrypt message
																																								ciphertext_len = encrypt(passwordError, strlen((char *)passwordError), client.symmetric_key, iv,ciphertext);

																																								memcpy(&newLine[0],&ciphertext_len,1);
																																								memcpy(&newLine[1],&iv[0],16);
																																								memcpy(&newLine[17],&ciphertext[0],ciphertext_len);


																																								send(client.from_socket,newLine,18+ciphertext_len, 0);


																																}

																																break;

																								default:
																																// no command was given
																																// TODO: send error message back
																																break;
																								}

																} else {
																								// TODO: Send error message back
																}
								}
}

void broadcast(struct client_info client) {

								unsigned char line[5000]=" ";
								int encryptedTextLength;
								unsigned char receivedIV[16]=" ";
								unsigned char encryptedText[5000]=" ";
								unsigned char newLine[5000]=" ";
								char finalString[5000]=" ";
								int decryptedtext_len, ciphertext_len;

								memcpy(line,client.message.substr(3).c_str(),strlen(client.message.c_str()) + 1);
								std::cout << "Message: " << line << '\n';

								// loop through our connected clients and create a string of connected clients id's
								for(std::map<std::string, struct client_info>::iterator it = connected_clients.begin(); it != connected_clients.end(); ++it) {

																// Check if it's us, otherwise say it's a client
																if (client.from_socket != it->second.from_socket) {

																								RAND_pseudo_bytes(iv,16);
																								//encrypt message
																								ciphertext_len = encrypt(line, strlen((char *)line), it->second.symmetric_key, iv,encryptedText);

																								memcpy(&newLine[0],&ciphertext_len,1);
																								memcpy(&newLine[1],&iv[0],16);
																								memcpy(&newLine[17],&encryptedText[0],ciphertext_len);

																								send(it->second.from_socket, newLine,18+ciphertext_len, 0);
																}
								}
}

void send_list(struct client_info client) {

								unsigned char ciphertext[5000];
								unsigned char newLine[5000];
								unsigned char decryptedtext[5000];
								int decryptedtext_len, ciphertext_len=0;
								unsigned char message[5000];
								std::string str_message;

								str_message.append("\n");

								// loop through our connected clients and create a string of connected clients id's
								for(std::map<std::string, struct client_info>::iterator it = connected_clients.begin();
												it != connected_clients.end(); ++it) {

																// Check if it's us, otherwise say it's a client
																if (client.from_socket == it->second.from_socket) {
																								str_message.append(it->first + ": You\n");
																} else {
																								str_message.append(it->first + ": Client\n");
																}
								}

								memcpy(message, str_message.c_str(),strlen(str_message.c_str())+1);

								RAND_pseudo_bytes(iv,16);
								//encrypt message
								ciphertext_len = encrypt(message, strlen((char *)message), client.symmetric_key, iv,ciphertext);

								memcpy(&newLine[0],&ciphertext_len,1);
								memcpy(&newLine[1],&iv[0],16);
								memcpy(&newLine[17],&ciphertext[0],ciphertext_len);

								send(client.from_socket,newLine,18+ciphertext_len,0);

}


std::string parse_id(std::string message) {

								std::string id;

								// loop through our connected clients to see if any of the ids match the requested id
								for(std::map<std::string, struct client_info>::iterator it = connected_clients.begin();
												it != connected_clients.end(); ++it) {
																if(message.find(it->first) == 3) {
																								std::cout << "Request for client: " << it->first << std::endl;
																								id = it->first;
																}
								}

								return id;
}

void terminate_user(struct client_info client) {

								unsigned char ciphertext[5000]="";
								unsigned char newLine[5000]="";
								unsigned char decryptedtext[5000]="";
								int decryptedtext_len, ciphertext_len=0;
								unsigned char message[5000]="";

								unsigned char terminating[] = "You are now disconnected from server..\n";

								//memcpy(message, client.message.substr(client.message.find(id) + 1).c_str(),strlen(client.message.substr(client.message.find(id) + 1).c_str())+1);

								RAND_pseudo_bytes(iv,16);
								//encrypt message
								ciphertext_len = encrypt(terminating, strlen((char *)terminating), client.symmetric_key, iv,ciphertext);
								//	std::cout << "Client Key: " << '\n';
								//	BIO_dump_fp (stdout, (const char *)client.symmetric_key, 32);

								memcpy(&newLine[0],&ciphertext_len,1);
								//std::cout << "Terminate cypher length: " << ciphertext_len<< '\n';
								memcpy(&newLine[1],&iv[0],16);

								//printf("IV is:\n");
								//BIO_dump_fp (stdout, (const char *)iv, 16);
								memcpy(&newLine[17],&ciphertext[0],ciphertext_len);
								//printf("Ciphertext is:\n");
								//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

								send(client.from_socket,newLine,18+ciphertext_len, 0);

								// remove the client from the list of connected clients
								connected_clients.erase(client.username);
}


int main(int argc, char** argv) {

								// port to listen on
								int port;
								//set up library

								ERR_load_crypto_strings();
								OpenSSL_add_all_algorithms();
								OPENSSL_config(NULL);

								// Create a TCP Socket
								int sockfd = socket(AF_INET, SOCK_STREAM, 0);

								FILE* privf = fopen("RSApriv.pem","rb");
								privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);



								struct sockaddr_in serveraddr, clientaddr;
								serveraddr.sin_family = AF_INET;
								serveraddr.sin_addr.s_addr = INADDR_ANY;

								std::cout << "Enter a port to listen on: ";
								std::cin >> port;
								std::cout << "\nListening on port " << port << std::endl;

								serveraddr.sin_port = htons(port);
								thread_setup();
								bind(sockfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
								listen(sockfd, 10);

								// our sending and receivng threads
								pthread_t receiver;

								while(true) {

																socklen_t len = sizeof(clientaddr);
																int clientsocket = accept(sockfd, (struct sockaddr*)&clientaddr, &len);

																struct client_info client;
																client.from_socket = clientsocket;
																client.ipaddr = clientaddr.sin_addr.s_addr;
																client.is_admin = false;

																// convert our int to a string
																std::stringstream ss;
																ss << clientsocket;

																// add our client to our map to map client id to client info
																connected_clients[std::string(ss.str())] = client;
																connected_clients[std::string(ss.str())].username = std::string(ss.str());

																// pass in our map's client_info struct, detach it
																pthread_create(&receiver, NULL, handle_receive, &connected_clients[std::string(ss.str())]);
																pthread_detach(receiver);
								}

								pthread_cancel(receiver);
								pthread_join(receiver, NULL);

								close(sockfd);

								return 0;
}



static const char rnd_seed[] =
								"string to make the random number generator think it has entropy";

int doit(char *ctx[4]);

static void print_stats(BIO *bio, SSL_CTX *ctx) {
								BIO_printf(bio, "%4ld items in the session cache\n",
																			SSL_CTX_sess_number(ctx));
								BIO_printf(bio, "%4d client connects (SSL_connect())\n",
																			SSL_CTX_sess_connect(ctx));
								BIO_printf(bio, "%4d client connects that finished\n",
																			SSL_CTX_sess_connect_good(ctx));
								BIO_printf(bio, "%4d server connects (SSL_accept())\n",
																			SSL_CTX_sess_accept(ctx));
								BIO_printf(bio, "%4d server connects that finished\n",
																			SSL_CTX_sess_accept_good(ctx));
								BIO_printf(bio, "%4d session cache hits\n", SSL_CTX_sess_hits(ctx));
								BIO_printf(bio, "%4d session cache misses\n", SSL_CTX_sess_misses(ctx));
								BIO_printf(bio, "%4d session cache timeouts\n", SSL_CTX_sess_timeouts(ctx));
}

static void sv_usage(void) {
								BIO_printf(bio_err, "usage: ssltest [args ...]\n");
								BIO_printf(bio_err, "\n");
								BIO_printf(bio_err, " -server_auth  - check server certificate\n");
								BIO_printf(bio_err, " -client_auth  - do client authentication\n");
								BIO_printf(bio_err, " -v            - more output\n");
								BIO_printf(bio_err, " -CApath arg   - PEM format directory of CA's\n");
								BIO_printf(bio_err, " -CAfile arg   - PEM format file of CA's\n");
								BIO_printf(bio_err, " -threads arg  - number of threads\n");
								BIO_printf(bio_err, " -loops arg    - number of 'connections', per thread\n");
								BIO_printf(bio_err, " -reconnect    - reuse session-id's\n");
								BIO_printf(bio_err, " -stats        - server session-id cache stats\n");
								BIO_printf(bio_err, " -cert arg     - server certificate/key\n");
								BIO_printf(bio_err, " -ccert arg    - client certificate/key\n");
								BIO_printf(bio_err, " -ssl3         - just SSLv3n\n");
}

#define W_READ  1
#define W_WRITE 2
#define C_DONE  1
#define S_DONE  2

int ndoit(SSL_CTX *ssl_ctx[2]) {
								int i;
								int ret;
								char *ctx[4];
								CRYPTO_THREADID thread_id;

								ctx[0] = (char *)ssl_ctx[0];
								ctx[1] = (char *)ssl_ctx[1];

								if (reconnect) {
																ctx[2] = (char *)SSL_new(ssl_ctx[0]);
																ctx[3] = (char *)SSL_new(ssl_ctx[1]);
								} else {
																ctx[2] = NULL;
																ctx[3] = NULL;
								}

								CRYPTO_THREADID_current(&thread_id);
								BIO_printf(bio_stdout, "started thread %lu\n",
																			CRYPTO_THREADID_hash(&thread_id));
								for (i = 0; i < number_of_loops; i++) {
																ret = doit(ctx);
																if (ret != 0) {
																								BIO_printf(bio_stdout, "error[%d] %lu - %d\n",
																																			i, CRYPTO_THREADID_hash(&thread_id), ret);
																								return (ret);
																}
								}

								BIO_printf(bio_stdout, "DONE %lu\n", CRYPTO_THREADID_hash(&thread_id));
								if (reconnect) {
																SSL_free((SSL *)ctx[2]);
																SSL_free((SSL *)ctx[3]);
								}
								return (0);
}

int doit(char *ctx[4]) {
								SSL_CTX *s_ctx, *c_ctx;
								static char cbuf[200], sbuf[200];
								SSL *c_ssl = NULL;
								SSL *s_ssl = NULL;
								BIO *c_to_s = NULL;
								BIO *s_to_c = NULL;
								BIO *c_bio = NULL;
								BIO *s_bio = NULL;
								int c_r, c_w, s_r, s_w;
								int c_want, s_want;
								int i;
								int done = 0;
								int c_write, s_write;
								int do_server = 0, do_client = 0;

								s_ctx = (SSL_CTX *)ctx[0];
								c_ctx = (SSL_CTX *)ctx[1];

								if (ctx[2] != NULL)
																s_ssl = (SSL *)ctx[2];
								else
																s_ssl = SSL_new(s_ctx);

								if (ctx[3] != NULL)
																c_ssl = (SSL *)ctx[3];
								else
																c_ssl = SSL_new(c_ctx);

								if ((s_ssl == NULL) || (c_ssl == NULL))
																goto err;

								c_to_s = BIO_new(BIO_s_mem());
								s_to_c = BIO_new(BIO_s_mem());
								if ((s_to_c == NULL) || (c_to_s == NULL))
																goto err;

								c_bio = BIO_new(BIO_f_ssl());
								s_bio = BIO_new(BIO_f_ssl());
								if ((c_bio == NULL) || (s_bio == NULL))
																goto err;

								SSL_set_connect_state(c_ssl);
								SSL_set_bio(c_ssl, s_to_c, c_to_s);
								BIO_set_ssl(c_bio, c_ssl, (ctx[2] == NULL) ? BIO_CLOSE : BIO_NOCLOSE);

								SSL_set_accept_state(s_ssl);
								SSL_set_bio(s_ssl, c_to_s, s_to_c);
								BIO_set_ssl(s_bio, s_ssl, (ctx[3] == NULL) ? BIO_CLOSE : BIO_NOCLOSE);

								c_r = 0;
								s_r = 1;
								c_w = 1;
								s_w = 0;
								c_want = W_WRITE;
								s_want = 0;
								c_write = 1, s_write = 0;

								/* We can always do writes */
								for (;;) {
																do_server = 0;
																do_client = 0;

																i = (int)BIO_pending(s_bio);
																if ((i && s_r) || s_w)
																								do_server = 1;

																i = (int)BIO_pending(c_bio);
																if ((i && c_r) || c_w)
																								do_client = 1;

																if (do_server && verbose) {
																								if (SSL_in_init(s_ssl))
																																BIO_printf(bio_stdout, "server waiting in SSL_accept - %s\n",
																																											SSL_state_string_long(s_ssl));
																								else if (s_write)
																																BIO_printf(bio_stdout, "server:SSL_write()\n");
																								else
																																BIO_printf(bio_stdout, "server:SSL_read()\n");
																}

																if (do_client && verbose) {
																								if (SSL_in_init(c_ssl))
																																BIO_printf(bio_stdout, "client waiting in SSL_connect - %s\n",
																																											SSL_state_string_long(c_ssl));
																								else if (c_write)
																																BIO_printf(bio_stdout, "client:SSL_write()\n");
																								else
																																BIO_printf(bio_stdout, "client:SSL_read()\n");
																}

																if (!do_client && !do_server) {
																								BIO_printf(bio_stdout, "ERROR IN STARTUP\n");
																								break;
																}
																if (do_client && !(done & C_DONE)) {
																								if (c_write) {
																																i = BIO_write(c_bio, "hello from client\n", 18);
																																if (i < 0) {
																																								c_r = 0;
																																								c_w = 0;
																																								if (BIO_should_retry(c_bio)) {
																																																if (BIO_should_read(c_bio))
																																																								c_r = 1;
																																																if (BIO_should_write(c_bio))
																																																								c_w = 1;
																																								} else {
																																																BIO_printf(bio_err, "ERROR in CLIENT\n");
																																																ERR_print_errors_fp(stderr);
																																																return (1);
																																								}
																																} else if (i == 0) {
																																								BIO_printf(bio_err, "SSL CLIENT STARTUP FAILED\n");
																																								return (1);
																																} else {
																																								/* ok */
																																								c_write = 0;
																																}
																								} else {
																																i = BIO_read(c_bio, cbuf, 100);
																																if (i < 0) {
																																								c_r = 0;
																																								c_w = 0;
																																								if (BIO_should_retry(c_bio)) {
																																																if (BIO_should_read(c_bio))
																																																								c_r = 1;
																																																if (BIO_should_write(c_bio))
																																																								c_w = 1;
																																								} else {
																																																BIO_printf(bio_err, "ERROR in CLIENT\n");
																																																ERR_print_errors_fp(stderr);
																																																return (1);
																																								}
																																} else if (i == 0) {
																																								BIO_printf(bio_err, "SSL CLIENT STARTUP FAILED\n");
																																								return (1);
																																} else {
																																								done |= C_DONE;
																																}
																								}
																}

																if (do_server && !(done & S_DONE)) {
																								if (!s_write) {
																																i = BIO_read(s_bio, sbuf, 100);
																																if (i < 0) {
																																								s_r = 0;
																																								s_w = 0;
																																								if (BIO_should_retry(s_bio)) {
																																																if (BIO_should_read(s_bio))
																																																								s_r = 1;
																																																if (BIO_should_write(s_bio))
																																																								s_w = 1;
																																								} else {
																																																BIO_printf(bio_err, "ERROR in SERVER\n");
																																																ERR_print_errors_fp(stderr);
																																																return (1);
																																								}
																																} else if (i == 0) {
																																								BIO_printf(bio_err, "SSL SERVER STARTUP FAILED\n");
																																								return (1);
																																} else {
																																								s_write = 1;
																																								s_w = 1;
																																}
																								} else {
																																i = BIO_write(s_bio, "hello from server\n", 18);
																																if (i < 0) {
																																								s_r = 0;
																																								s_w = 0;
																																								if (BIO_should_retry(s_bio)) {
																																																if (BIO_should_read(s_bio))
																																																								s_r = 1;
																																																if (BIO_should_write(s_bio))
																																																								s_w = 1;
																																								} else {
																																																BIO_printf(bio_err, "ERROR in SERVER\n");
																																																ERR_print_errors_fp(stderr);
																																																return (1);
																																								}
																																} else if (i == 0) {
																																								BIO_printf(bio_err, "SSL SERVER STARTUP FAILED\n");
																																								return (1);
																																} else {
																																								s_write = 0;
																																								s_r = 1;
																																								done |= S_DONE;
																																}
																								}
																}

																if ((done & S_DONE) && (done & C_DONE))
																								break;
								}

								SSL_set_shutdown(c_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
								SSL_set_shutdown(s_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

err:
								/*
								 * We have to set the BIO's to NULL otherwise they will be free()ed
								 * twice.  Once when th s_ssl is SSL_free()ed and again when c_ssl is
								 * SSL_free()ed. This is a hack required because s_ssl and c_ssl are
								 * sharing the same BIO structure and SSL_set_bio() and SSL_free()
								 * automatically BIO_free non NULL entries. You should not normally do
								 * this or be required to do this
								 */

								if (s_ssl != NULL) {
																s_ssl->rbio = NULL;
																s_ssl->wbio = NULL;
								}
								if (c_ssl != NULL) {
																c_ssl->rbio = NULL;
																c_ssl->wbio = NULL;
								}

								/* The SSL's are optionally freed in the following calls */
								if (c_to_s != NULL)
																BIO_free(c_to_s);
								if (s_to_c != NULL)
																BIO_free(s_to_c);

								if (c_bio != NULL)
																BIO_free(c_bio);
								if (s_bio != NULL)
																BIO_free(s_bio);
								return (0);
}

int verify_callback(int ok, X509_STORE_CTX *ctx)
{
								char *s, buf[256];

								if (verbose) {
																s = X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),
																																						buf, 256);
																if (s != NULL) {
																								if (ok)
																																BIO_printf(bio_err, "depth=%d %s\n", ctx->error_depth, buf);
																								else
																																BIO_printf(bio_err, "depth=%d error=%d %s\n",
																																											ctx->error_depth, ctx->error, buf);
																}
								}
								return (ok);
}

#define THREAD_STACK_SIZE (16*1024)

// #ifdef PTHREADS

static pthread_mutex_t *lock_cs;
static long *lock_count;

void thread_setup(void)
{
								int i;

								lock_cs = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
								lock_count = (long int *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
								for (i = 0; i < CRYPTO_num_locks(); i++) {
																lock_count[i] = 0;
																pthread_mutex_init(&(lock_cs[i]), NULL);
								}

								CRYPTO_THREADID_set_callback(pthreads_thread_id);
								CRYPTO_set_locking_callback(pthreads_locking_callback);
}

void thread_cleanup(void)
{
								int i;

								CRYPTO_set_locking_callback(NULL);
								BIO_printf(bio_err, "cleanup\n");
								for (i = 0; i < CRYPTO_num_locks(); i++) {
																pthread_mutex_destroy(&(lock_cs[i]));
																BIO_printf(bio_err, "%8ld:%s\n", lock_count[i], CRYPTO_get_lock_name(i));
								}
								OPENSSL_free(lock_cs);
								OPENSSL_free(lock_count);

								BIO_printf(bio_err, "done cleanup\n");
}

void pthreads_locking_callback(int mode, int type, const char *file, int line)
{
# ifdef undef
								BIO_printf(bio_err, "thread=%4d mode=%s lock=%s %s:%d\n",
																			CRYPTO_thread_id(),
																			(mode & CRYPTO_LOCK) ? "l" : "u",
																			(type & CRYPTO_READ) ? "r" : "w", file, line);
# endif
/*-
    if (CRYPTO_LOCK_SSL_CERT == type)
            BIO_printf(bio_err,"(t,m,f,l) %ld %d %s %d\n",
                       CRYPTO_thread_id(),
                       mode,file,line);
 */
								if (mode & CRYPTO_LOCK) {
																pthread_mutex_lock(&(lock_cs[type]));
																lock_count[type]++;
								} else {
																pthread_mutex_unlock(&(lock_cs[type]));
								}
}

void do_threads(SSL_CTX *s_ctx, SSL_CTX *c_ctx)
{
								SSL_CTX *ssl_ctx[2];
								pthread_t thread_ctx[MAX_THREAD_NUMBER];
								int i;

								ssl_ctx[0] = s_ctx;
								ssl_ctx[1] = c_ctx;

								/*
								 * thr_setconcurrency(thread_number);
								 */
								for (i = 0; i < thread_number; i++) {
																pthread_create(&(thread_ctx[i]), NULL,
																															(void *(*)(void *))ndoit, (void *)ssl_ctx);
								}

								BIO_printf(bio_stdout, "reaping\n");
								for (i = 0; i < thread_number; i++) {
																pthread_join(thread_ctx[i], NULL);
								}

#if 0 /* We can't currently find out the reference amount */
								BIO_printf(bio_stdout, "pthreads threads done (%d,%d)\n",
																			s_ctx->references, c_ctx->references);
#else
								BIO_printf(bio_stdout, "pthreads threads done\n");
#endif
}

void pthreads_thread_id(CRYPTO_THREADID *tid)
{
								CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

// #endif                          /* PTHREADS */

int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){
								EVP_PKEY_CTX *ctx;
								size_t outlen;
								ctx = EVP_PKEY_CTX_new(key,NULL);
								if (!ctx)
																handleErrors();
								if (EVP_PKEY_decrypt_init(ctx) <= 0)
																handleErrors();
								if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
																handleErrors();
								if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
																handleErrors();
								if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
																handleErrors();
								return outlen;
}
void handleErrors(void)
{
								ERR_print_errors_fp(stderr);
								abort();
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
