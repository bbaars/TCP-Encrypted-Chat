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

int main(int argc, char** argv)
{
	bool run = true;
	int sockfd = socket(AF_INET,SOCK_STREAM,0);
	int port = 0;
	int i;
	fd_set sockets;
	FD_ZERO(&sockets);

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
	"\n-a [password]               request admin status"
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
				printf("Enter a command: ");
				char line[5000];
				fgets(line, 5000, stdin);
				send(sockfd,line,strlen(line)+1,0);
			}

			/*If the server is sending something to the client*/
			else if (i == sockfd)
			{
				char line[5000];
				recv(sockfd,line,5000,0);

				/*If quit message was received, exit*/
				if (strstr(line, "disconnected from server") != NULL)
				{
					run = false;
					printf("Disconnected from servers\n"); //Newline
					break;
				}
				printf("\nGot from server: %s\nEnter a command: ",line);
				fflush(stdout);
			}
		}
	}
}

close(sockfd);
return 0;

}
