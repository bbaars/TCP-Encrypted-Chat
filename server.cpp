/*
 * @authors: Brandon Baars, Mike Ford, Isaac Benson
 * @date: 03/15/2018
 * @description: CIS 457 Project 3: TCP Encrytped Chat Server
 *
 */

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

// FUNCTION DECLARATIONS
void parse_message(struct client_info & client);
void * handle_receive(void * client_arg);
void send_list(struct client_info client);
void terminate_user(struct client_info client);
std::string parse_id(std::string message);
void broadcast(struct client_info client);

// Struct that handles our clients request.
struct client_info {

								int from_socket; // socket the request was from
								uint32_t ipaddr; // ip address of the client
								std::vector<int> to_socket; // vector to hold the sockets to send to (broadcast or 1)
								std::string message; // message the client wants to send
								bool is_admin; // whether or not the client has admin access
								pthread_t id; // thread id that this client is attached to
								std::string username; // the username of the client (used to map itself to the map?)
};

// list of all the connected clients
std::map<std::string, struct client_info> connected_clients;

//Global password
std::string PASSWORD = "password";


/*
 *	Handle the connection received with the client
 */
void * handle_receive(void * client_arg) {

								struct client_info client = *(struct client_info*) client_arg;
								struct in_addr ipaddr;
								ipaddr.s_addr = client.ipaddr;

								std::cout << "Received client: " << client.from_socket << " from IP Addr: "
																		<< inet_ntoa(ipaddr) << std::endl;

								// while there is still an active connection with the client
								bool is_running = true;

								client.id = pthread_self();

								while(is_running) {

																char line[5000];
																int rec = recv(client.from_socket, line, 5000, 0);

																std::string str_line(line);
																client.message = str_line;

																//if there was a message received with more than a command (i.e 2 characters -L)
																if (rec >= 2) {
																								parse_message(client);
																}
								}
}


void parse_message(struct client_info & client) {

								// There was an argument given
								if(client.message.find("-") == 0) {

																// make sure we don't get index out of bounds
																if (client.message.length() >= 2) {

																								// get the command issued by the client
																								char command = client.message.at(1);
																								std::string id;

																								char error[] = "Sorry, there was an error";
																								char passwordError[] = "Incorrect Password.";
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
																																								send(connected_clients[id].from_socket,
																																													client.message.substr(client.message.find(id) + 1).c_str(),
																																													strlen(client.message.substr(client.message.find(id)).c_str()), 0);
																																} else {
																																								// Send messge back to client saying can't send message to self
																																								send(client.from_socket, error, strlen(error) + 1, 0);
																																}

																																break;
																								case 'B':
																								case 'b':
																																// broadcast messagee
																																broadcast(client);
																																break;
																								case 'k':
																								case 'K':
																																// parse for recipient id
																																// Kill user

																																break;
																								case 'q':
																								case 'Q':
																																// close the thread and remove client from active list
																																terminate_user(client);
																																break;

																								case 'a':
																								case 'A':
																																if(client.message.substr(client.message.find("-")+3).compare(PASSWORD) == 0)
																																								client.is_admin = true;
																																else
																																{
																																								send(client.from_socket, passwordError, strlen(passwordError) + 1, 0);
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

								// loop through our connected clients and create a string of connected clients id's
								for(std::map<std::string, struct client_info>::iterator it = connected_clients.begin();
												it != connected_clients.end(); ++it) {

																// Check if it's us, otherwise say it's a client
																if (client.from_socket != it->second.from_socket) {
																								send(it->second.from_socket, client.message.substr(3).c_str(), strlen(client.message.c_str()) + 1, 0);
																}
								}
}

void send_list(struct client_info client) {

								char message[500];
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

								strcpy(message, str_message.c_str());
								send(client.from_socket, message, strlen(message) + 1, 0);
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

								char terminating[] = "You are not disconnected from server..\n";

								send(client.from_socket, terminating, strlen(terminating) + 1, 0);

								// remove the client from the list of connected clients
								connected_clients.erase(client.username);
								pthread_exit(NULL);
}


int main(int argc, char** argv) {

								// port to listen on
								int port;

								// Create a TCP Socket
								int sockfd = socket(AF_INET, SOCK_STREAM, 0);
								int total_connected = 0;

								struct sockaddr_in serveraddr, clientaddr;
								serveraddr.sin_family = AF_INET;
								serveraddr.sin_addr.s_addr = INADDR_ANY;

								std::cout << "Enter a port to listen on: ";
								std::cin >> port;
								std::cout << "\nListening on port " << port << std::endl;

								serveraddr.sin_port = htons(port);

								bind(sockfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
								listen(sockfd, 10);

								// our sending and receivng threads
								pthread_t receiver, sender;


								while(true) {

																socklen_t len = sizeof(clientaddr);
																int clientsocket = accept(sockfd, (struct sockaddr*)&clientaddr, &len);

																struct client_info client;
																client.from_socket = clientsocket;
																client.ipaddr = clientaddr.sin_addr.s_addr;

																// convert our int to a string
																std::stringstream ss;
																ss << total_connected;

																// add our client to our map to map client id to client info
																connected_clients[std::string(ss.str())] = client;
																connected_clients[std::string(ss.str())].username = std::string(ss.str());

																// pass in our map's client_info struct
																pthread_create(&receiver, NULL, handle_receive, &connected_clients[std::string(ss.str())]);
																pthread_detach(receiver);
																total_connected++;
								}

								pthread_cancel(receiver);
								pthread_join(receiver, NULL);


								close(sockfd);

								return 0;
}
