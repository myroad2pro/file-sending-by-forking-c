#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include "protocol.h"

#define PAYLOAD_SIZE 65335
#define BUFF_SIZE 10240

struct message *recv_msg(int conn_sock);
int send_msg(int conn_sock, struct message msg, int length);
int send_eof_msg(int conn_sock);
int welcome();
int get_key();
int send_key(int conn_sock, int user_choice, int key);
int send_file(int client_sock, char *filename);
int recv_file(int client_sock);

int main(int argc, char *argv[]){
	int client_sock;
	struct sockaddr_in server_addr; /* server's address information */
	int serv_port = 0;
	char serv_ip[16];
	char *endptr;
	int user_choice = 0, key = 0;
	char filename[1024];

	// Step 1: Get command from terminal
	if(argc != 3){
		printf("Invalid arguments!\n");
		exit(-1);
	}

	strcpy(serv_ip, argv[1]);
	serv_port = (in_port_t) strtol(argv[2], &endptr, 10);
	if(strlen(endptr) != 0){
		printf("Invalid port!\n");
		exit(-1);
	}

	//Step 2: Construct socket
	client_sock = socket(AF_INET,SOCK_STREAM,0);
	
	//Step 3: Specify server address
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(serv_port);
	server_addr.sin_addr.s_addr = inet_addr(serv_ip);
	
	//Step 4: Request to connect server
	if(connect(client_sock, (struct sockaddr*)&server_addr, sizeof(struct sockaddr)) < 0){
		printf("\nError!Can not connect to sever! Client exit imediately! ");
		return 0;
	}
	
	//Step 5: Communicate with server			
	while(1){
		// input user choice and key
		user_choice = welcome();
		switch(user_choice){
			case 1:		// Encryptiion
			case 2:		// Decryption
				if((key = get_key()) == -1) continue;
				printf("Key: %d\n", key);
				if(send_key(client_sock, user_choice, key) == -1) continue;
				printf("Key sent successful\n");
				if(send_file(client_sock, filename) == -1) continue;
				if(recv_file(client_sock) == -1) continue;
				break;
			case 0:		// Exit the program
				printf("Exiting...\n\n");
				send_key(client_sock, user_choice, 0);
				return 0;
			default:	// Wrong user choice
				break;
		}
	}
	
	//Step 4: Close socket
	close(client_sock);
	return 0;
}

struct message *recv_msg(int conn_sock){
	long int msg_len = 0;
	int bytes_received = recv(conn_sock, &msg_len, sizeof(long int), MSG_WAITALL);
	if (bytes_received <= 0){
		return NULL;
	}

	int ret, nLeft, index = 0;
	char recv_data[BUFF_SIZE];
	char *data = (char *) malloc(sizeof(struct message));
	memset(data, 0, sizeof(struct message));
	nLeft = msg_len;
	index = 0;
	
	//receives message from client
	while(nLeft > 0){
		ret = recv(conn_sock, recv_data, BUFF_SIZE, 0);
		if(ret == -1){
			return NULL;
		}
		memcpy(data + index, recv_data, ret);
		index += ret;
		nLeft -= ret;
	}
	data[msg_len] = '\0';
	struct message *msg = (struct message *) malloc(sizeof(struct message));
	memcpy(msg, data, sizeof(struct message));
	return msg;
}

int send_msg(int conn_sock, struct message msg, int length){
	int bytes_sent = 0;
	long int msg_len = sizeof(struct message) - PAYLOAD_SIZE + length - 1;
	//send the length of the message to server
	bytes_sent = send(conn_sock, &msg_len, sizeof(long int), 0);
	if(bytes_sent <= 0){
		return -1;
	}

	// send the message to server
	bytes_sent = send(conn_sock, &msg, msg_len, 0);
	if (bytes_sent <= 0){
		return -1;
	}
	return 0;
}

int send_eof_msg(int conn_sock){
	int bytes_sent = 0;
	long int msg_len = sizeof(struct message) - PAYLOAD_SIZE - 1;
	struct message msg;
	bytes_sent = send(conn_sock, &msg_len, sizeof(long int), 0);
	if(bytes_sent <= 0){
		return -1;
	}

	// send the message to server
	msg.opcode = '2';
	msg.length = 0;
	memset(msg.payload, 0, PAYLOAD_SIZE);
	bytes_sent = send(conn_sock, &msg, msg_len, 0);
	if (bytes_sent <= 0){
		return -1;
	}
	return 0;
}

int welcome(){
	int user_choice;

	printf("TCP File Encryption/Decryption Application\n");
	printf("Nguyen Hoang Anh - 20130135\n");
	printf("Choose one of the following options:\n");
	printf("1. File Encryption\n2.File Decryption\n0. Exit\n");
	printf("Your choice: ");
	scanf("%d", &user_choice);
	while(getchar() != '\n');
	switch(user_choice){
		case 1:
		case 2:
		case 0:
			return user_choice;
		default:
			printf("Invalid choice! Returning to menu...\n\n");
			return -1;
	}
}

int get_key(){
	int key;
	printf("Please input your key (from 0 to 255): ");
	scanf("%d", &key);
	while(getchar() != '\n');
	if(key < 0 || key > 255){
		printf("Invalid key! Returning to menu...\n\n");
		return -1;
	}
	return key;
}

int send_key(int conn_sock, int user_choice, int key){
	struct message msg;
	if(user_choice == 1){	// Encryption
		msg.opcode = '0';
	}else if(user_choice == 2){		// Decryption
		msg.opcode = '1';
	}else if(user_choice == 0){
		msg.opcode = '3';
		msg.length = 0;
		send_msg(conn_sock, msg, msg.length);
		return 0;
	}

	sprintf(msg.payload, "%d", key);
	msg.length = strlen(msg.payload);

	if(send_msg(conn_sock, msg, msg.length) == -1){
		printf("Key transfering interupted!\n");
		return -1;
	}
	return 0;
}

int send_file(int client_sock, char *filename){
	FILE *fp = NULL;
	double bytes_transfered = 0;
	char filelink[1024];
	struct message msg, *reply;
	long int filesize;

	printf("File link: ");
	memset(filelink, 0, 1024);
	fgets(filelink, 1024, stdin);
	filelink[strlen(filelink) - 1] = '\0';
	if (strlen(filelink) == 0) return -1;

	// open file to read
	if((fp = fopen(filelink, "rb")) == NULL){
		printf("Error: File not found\n");
		msg.opcode = '3';
		msg.length = 0;
		if(send_msg(client_sock, msg, msg.length) == -1){
			fclose(fp);
			printf("Error: File sending is interupted\n\n");
			return -1;
		}
		recv_msg(client_sock);
		return -1;
	}else{
		// extract filename from link
		if(strchr(filelink, '/')) strcpy(filename, rindex(filelink, '/') + 1);
		else strcpy(filename, filelink);
		// send filename to server
		memset(msg.payload, 0, PAYLOAD_SIZE);
		msg.opcode = '2';
		msg.length = strlen(filename);
		strcpy(msg.payload, filename);
		if(send_msg(client_sock, msg, msg.length) == -1){
			fclose(fp);
			printf("Error: File sending is interupted\n\n");
			return -1;
		}
		recv_msg(client_sock);

		// get file size
		fseek(fp, 0, SEEK_END); // seek to end of file
		filesize = ftell(fp); // get current file pointer
		fseek(fp, 0, SEEK_SET); // seek back to beginning of file
		printf("Filesize: %ld\n", filesize);

		// send file size to server
		memset(msg.payload, 0, PAYLOAD_SIZE);
		msg.opcode = '2';
		sprintf(msg.payload, "%ld", filesize);
		msg.length = strlen(msg.payload);
		if(send_msg(client_sock, msg, msg.length) == -1){
			fclose(fp);
			printf("Error: Filesize sending is interupted\n\n");
			return -1;
		}
		recv_msg(client_sock);
		// send file content
		while(msg.opcode != '3' && filesize > 0){		// until there is an error, keep reading from file
			msg.opcode = '2';
			msg.length = PAYLOAD_SIZE;
			memset(msg.payload, 0, PAYLOAD_SIZE);
			if(filesize > PAYLOAD_SIZE){
				// send the block to server
				fread(msg.payload, PAYLOAD_SIZE, 1, fp);
				if(send_msg(client_sock, msg, PAYLOAD_SIZE) == -1){
					fclose(fp);
					printf("Error: File sending is interupted\n\n");
					return -1;
				}
				printf("Total payload sent: %.2lf MB\n", (bytes_transfered += PAYLOAD_SIZE) / (1024*1024));
				filesize -= PAYLOAD_SIZE;
			}else{ // if EOF has been reached
				// send the last block of file
				fread(msg.payload, filesize, 1, fp);
				if(send_msg(client_sock, msg, filesize) == -1){
					fclose(fp);
					printf("Error: File sending is interupted\n\n");
					return -1;
				}
				printf("Total payload sent: %.2lf MB\n", (bytes_transfered += filesize) / (1024*1024));
				
				// check if there is any error
				if((reply = recv_msg(client_sock)) == NULL) return -1;
				msg.opcode = reply->opcode;
				free(reply);

				// send EOF signal to server
				msg.length = 0;
				if(send_eof_msg(client_sock) == -1){
					fclose(fp);
					printf("Error: File sending is interupted\n\n");
					return -1;
				}
				break;
			}
			// check if there is any error
			if((reply = recv_msg(client_sock)) == NULL) return -1;
			msg.opcode = reply->opcode;
			free(reply);
		}
		if(msg.opcode == '2'){
			printf("File sending successful.\n\n");
		}else if(msg.opcode == '3'){
			printf("Error!!!\n\n");
		}
	}
	fclose(fp);
	return 0;
}

int recv_file(int client_sock){
	FILE *fp = NULL;
	double bytes_transfered = 0;
	struct message *msg;
	struct message error_message = {'2', 0, ""};
	time_t timestamp;
    struct tm *calendar;
    time(&timestamp);
    calendar = localtime(&timestamp);
    char *filelink = (char*) malloc(1024);
    char filename[1024];
    char file_extension[10];
    long int filesize;

	// create new file
	// receive filename from server
    if((msg = recv_msg(client_sock))){
    	strcpy(filename, msg->payload);
    	send_msg(client_sock, error_message, 0);
    }else{
    	printf("Filename receiving interupted!\n\n");
    	error_message.opcode = '3';
    	send_msg(client_sock, error_message, 0);
    	return -1;
    }

    // receive filesize from client
    if((msg = recv_msg(client_sock))){
    	filesize = atol(msg->payload);
    	send_msg(client_sock, error_message, 0);
    }else{
    	printf("Filesize receiving interupted!\n\n");
    	error_message.opcode = '3';
    	send_msg(client_sock, error_message, 0);
    	return -1;
    }

    printf("Filename: %s\nFilesize: %ld\n", filename, filesize);
    // reserve file extension
    strcpy(file_extension, rindex(filename, '.'));
	// create new file
	sprintf(filelink, "./data/%d%d%d%d%d%d%s", calendar->tm_year, calendar->tm_mon, calendar->tm_mday, 
    calendar->tm_hour, calendar->tm_min, calendar->tm_sec, file_extension);
	fp = fopen(filelink, "wb+");
	printf("File: %s\n", filelink);
	bytes_transfered = 0;

	while((msg = recv_msg(client_sock))){
		if(msg->opcode == '2' && msg->length > 0 && filesize > 0){		// if file content is received
			printf("Total payload received: %.2lf MB\n", (bytes_transfered += msg->length) / (1024 * 1024));
			if(filesize >= PAYLOAD_SIZE) fwrite(msg->payload, msg->length, 1, fp);
			else fwrite(msg->payload, filesize, 1, fp);
			send_msg(client_sock, error_message, 0);
			free(msg);
			filesize -= PAYLOAD_SIZE;
		}else if(msg->opcode == '2' && msg->length == 0){		// if file reached EOF
			printf("Successfully received\n\n");
			free(msg);
			fclose(fp);
			return 0;
		}		
	}
	// if file transfering is interupted
	error_message.opcode = '3';
	printf("Error: File receiving is interupted\n\n");
	send_msg(client_sock, error_message, 0);
	fclose(fp);
	return -1;
}
