#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

int isRunning = 1;

pthread_t tmp_thread, tmp2_thread;

void* handleReceive(void * arg) {
  int socket = *(int *) arg;


  while(isRunning) {
  
	char line[5000];
    int rec = recv(socket,line,5000,0);
        
    printf("Got from server: %s\n", line);
  }

  return NULL;
}

void* handleSend(void * arg) {

  int socket = *(int *) arg;

 
  while (isRunning) {
  
  	char line[5000];
    printf("Send to server: ");
    fgets(line, 5000, stdin);

    send(socket, line, strlen(line) + 1, 0);
  }
  
  return NULL;
}


int main(int argc, char** argv) {
  int sockfd = socket(AF_INET,SOCK_STREAM,0);
  char ipAddress[11], port[10];

  if(sockfd<0){
    printf("There was an error creating the socket\n");
    return 1;
  }
  
  	printf("Welcome to the client...");

	// create the server address and prompt user for input
	struct sockaddr_in serveraddr;
	serveraddr.sin_family = AF_INET;

	printf("\nEnter a port number to connect to: ");
	fgets(port, 10, stdin);
	serveraddr.sin_port = htons(atoi(port));

	// printf("\nEnter the IP Address of the server: ");
	// fgets(ipAddress, 11, stdin);
	// serveraddr.sin_addr.s_addr = inet_addr(&ipAddress);
	serveraddr.sin_addr.s_addr=inet_addr("127.0.0.1");
	
  int e = connect(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
  
  if(e<0) {
    printf("There was an error connecting\n");
    return 1;
  }

    pthread_t receive, sender;
    pthread_create(&receive, NULL, handleReceive, &sockfd);
    pthread_create(&sender, NULL, handleSend, &sockfd);

    while(isRunning)
      ;

   // pthread_detach(receive);
   // pthread_detach(sender);
  	pthread_join(receive, NULL);
   	pthread_join(sender, NULL);
   	
    close(sockfd);
    
    return 0;
}
