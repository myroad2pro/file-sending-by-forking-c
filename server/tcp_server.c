#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include "protocol.h"

#define BACKLOG 20
#define PAYLOAD_SIZE 65335
#define BUFF_SIZE 10240

struct message *recv_msg(int conn_sock);
int send_msg(int conn_sock, struct message msg, int length);
int send_eof_msg(int conn_sock);
int recv_key(int conn_sock, char *user_choice, int *key);
int send_file(int client_sock, char *filelink);
char *recv_file(int client_sock);
char *caesar_encryption(char *plaintext, int key, long int buffsize);
char *caesar_decryption(char *plaintext, int key, long int buffsize);
char *file_encryption(char *filelink, int key);
char *file_decryption(char *filelink, int key);

/* Handler process signal*/
void sig_chld(int signo);

/*
* Receive, encrypt/decrypt and send file to client
* [IN] sockfd: socket descriptor that connects to client 	
*/
int child_process(int sockfd);

int main(int argc, char *argv[]){
	int listen_sock, conn_sock; /* file descriptors */
	struct sockaddr_in server; /* server's address information */
	struct sockaddr_in client; /* client's address information */
	pid_t pid;
	int sin_size;
	int serv_port;
	char *endptr;

	if(argc != 2){
		printf("Invalid arguments\n");
		exit(-1);
	}
	serv_port = (in_port_t) strtol(argv[1], &endptr, 10);
	if(strlen(endptr) != 0){
		printf("Invalid port!\n");
		exit(-1);
	}

	if ((listen_sock=socket(AF_INET, SOCK_STREAM, 0)) == -1 ){  /* calls socket() */
		printf("socket() error\n");
		return 0;
	}
	
	bzero(&server, sizeof(server));
	server.sin_family = AF_INET;         
	server.sin_port = htons(serv_port);
	server.sin_addr.s_addr = htonl(INADDR_ANY);  /* INADDR_ANY puts your IP address automatically */   

	if(bind(listen_sock, (struct sockaddr*)&server, sizeof(server))==-1){ 
		perror("\nError: ");
		return 0;
	}     

	if(listen(listen_sock, BACKLOG) == -1){  
		perror("\nError: ");
		return 0;
	}
	
	/* Establish a signal handler to catch SIGCHLD */
	signal(SIGCHLD, sig_chld);

	while(1){
		sin_size=sizeof(struct sockaddr_in);
		if ((conn_sock = accept(listen_sock, (struct sockaddr *)&client, &sin_size))==-1){
			if (errno == EINTR)
				continue;
			else{
				perror("\nError: ");			
				return 0;
			}
		}
		
		/* For each client, fork spawns a child, and the child handles the new client */
		pid = fork();
		
		/* fork() is called in child process */
		if(pid  == 0){
			close(listen_sock);
			printf("You got a connection from %s\n", inet_ntoa(client.sin_addr)); /* prints client's IP */
			child_process(conn_sock);
			exit(0);
		}
		
		/* The parent closes the connected socket since the child handles the new client */
		close(conn_sock);
	}
	close(listen_sock);
	return 0;
}

void sig_chld(int signo){
	pid_t pid;
	int stat;
	
	/* Wait the child process terminate */
	while((pid = waitpid(-1, &stat, WNOHANG))>0)
		printf("\nChild %d terminated\n",pid);
}

int child_process(int sockfd) {
	char *filelink;
	char user_choice;
	int key;
	
	while(1){
		if(recv_key(sockfd, &user_choice, &key) == -1){
			close(sockfd);
			return -1;	
		}
		if(user_choice == '3'){
			close(sockfd);
			return 0;
		}
		printf("Key: %d\n", key);
		if((filelink = recv_file(sockfd)) == NULL){
			close(sockfd);
			return -1;	
		}
		printf("Temp file: %s\n", filelink);
		if(user_choice == '0'){
			filelink = file_encryption(filelink, key);
		}else if(user_choice == '1'){
			filelink = file_decryption(filelink, key);
		}
		printf("Temp file: %s\n", filelink);
		send_file(sockfd, filelink);
		remove(filelink);	
	}
	
	close(sockfd);
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

int recv_key(int conn_sock, char *user_choice, int *key){
	struct message *msg;
	if((msg = recv_msg(conn_sock)) == NULL){
		printf("Key transfering interupted\n\n");
		return -1;
	}
	*user_choice = msg->opcode;
	if(*user_choice != '3') *key = atoi(msg->payload);
	free(msg);
	return 0;
}

int send_file(int client_sock, char *filelink){
	FILE *fp = NULL;
	double bytes_transfered = 0;
	struct message msg, *reply;
	char filename[1024];
	long int filesize;

	if (strlen(filelink) == 0) return -1;

	// open file to read
	if((fp = fopen(filelink, "rb")) == NULL){
		printf("Error: File not found\n");
		return -1;
	}else{
		// extract filename from link
		if(strchr(filelink, '/')) strcpy(filename, rindex(filelink, '/') + 1);
		else strcpy(filename, filelink);

		// send filename to server
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

		while(msg.opcode != '3' && filesize > 0){		// until there is an error, keep reading from file
			msg.opcode = '2';
			msg.length = PAYLOAD_SIZE;
			memset(msg.payload, 0, PAYLOAD_SIZE);
			if(filesize > PAYLOAD_SIZE){
				// send the block to server
				fread(msg.payload, PAYLOAD_SIZE, 1, fp);
				if(send_msg(client_sock, msg, PAYLOAD_SIZE) == -1){
					fclose(fp);
					printf("Error: File transfering is interupted\n\n");
					return -1;
				}
				printf("Total payload sent: %.2lf MB\n", (bytes_transfered += PAYLOAD_SIZE) / (1024*1024));
				filesize -= PAYLOAD_SIZE;
			}else{ // if EOF has been reached
				// send the last block of file
				fread(msg.payload, filesize, 1, fp);
				if(send_msg(client_sock, msg, filesize) == -1){
					fclose(fp);
					printf("Error: File transfering is interupted\n\n");
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
					printf("Error: File transfering is interupted\n\n");
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
			printf("File transfering successful.\n\n");
		}else if(msg.opcode == '3'){
			printf("Error!!!\n\n");
		}
	}
	fclose(fp);
	return 0;
}

char *recv_file(int client_sock){
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

    // receive filename from client
    if((msg = recv_msg(client_sock))){
    	if(msg->opcode == '3'){
    		error_message.opcode = '3';
    		send_msg(client_sock, error_message, 0);
    		return NULL;
    	}
    	strcpy(filename, msg->payload);
    	send_msg(client_sock, error_message, 0);
    }else{
    	printf("Filename receiving interupted!\n\n");
    	error_message.opcode = '3';
    	send_msg(client_sock, error_message, 0);
    	return NULL;
    }

    // receive filesize from client
    if((msg = recv_msg(client_sock))){
    	filesize = atol(msg->payload);
    	send_msg(client_sock, error_message, 0);
    }else{
    	printf("Filesize receiving interupted!\n\n");
    	error_message.opcode = '3';
    	send_msg(client_sock, error_message, 0);
    	return NULL;
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
			free(msg);
			send_msg(client_sock, error_message, 0);
			filesize -= PAYLOAD_SIZE;
		}else if(msg->opcode == '2' && msg->length == 0){		// if file reached EOF
			printf("Successfully received\n\n");
			fclose(fp);
			free(msg);
			return filelink;
		}
	}
	// if file transfering is interupted, send error message and delete the file
	error_message.opcode = '3';
	printf("Error: File receiving is interupted\n\n");
	send_msg(client_sock, error_message, 0);
	fclose(fp);
	remove(filelink);
	return NULL;
}

char *caesar_encryption(char *plaintext, int key, long int buffsize){
	int i;
	char *cipher = (char *) malloc(buffsize);
	for(i = 0; i < buffsize; i++){
		cipher[i] = (plaintext[i] + key)%256;
	}
	return cipher;
}

char *caesar_decryption(char *plaintext, int key, long int buffsize){
	int i;
	char *cipher = (char *) malloc(buffsize);
	for(i = 0; i < buffsize; i++){
		cipher[i] = (plaintext[i] - key)%256;
	}
	return cipher;
}

char *file_encryption(char *filelink, int key){
	FILE *fp1 = fopen(filelink, "rb");
	char buff[PAYLOAD_SIZE], *encrypted_data;
	time_t timestamp;
    struct tm *calendar;
    time(&timestamp);
    calendar = localtime(&timestamp);
    char *new_filename = (char*) malloc(1024);
    long int filesize;

    // create new encryption file
	sprintf(new_filename, "./data/%d%d%d%d%d%d%s", calendar->tm_year, calendar->tm_mon, calendar->tm_mday, 
    calendar->tm_hour, calendar->tm_min, calendar->tm_sec, rindex(filelink, '.'));
    FILE *fp2 = fopen(new_filename, "wb+");

    // get file size
    fseek(fp1, 0, SEEK_END); // seek to end of file
    filesize = ftell(fp1); // get current file pointer
    fseek(fp1, 0, SEEK_SET); // seek back to beginning of file
    printf("Filesize: %ld\n", filesize);

	// file encryption
	while(filesize > 0){
		if(filesize > PAYLOAD_SIZE){
			fread(buff, PAYLOAD_SIZE, 1, fp1);
			encrypted_data = caesar_encryption(buff, key, PAYLOAD_SIZE);
			fwrite(encrypted_data, PAYLOAD_SIZE, 1, fp2);
			filesize -= PAYLOAD_SIZE;
		}else{
			// read the last block of file
			fread(buff, filesize, 1, fp1);
			encrypted_data = caesar_encryption(buff, key, filesize);
			fwrite(encrypted_data, filesize, 1, fp2);
			filesize = 0;
		}
		free(encrypted_data);
	}
	fclose(fp1);
	fclose(fp2);
	remove(filelink);

	return new_filename;
}

char *file_decryption(char *filelink, int key){
	FILE *fp1 = fopen(filelink, "rb");
	char buff[PAYLOAD_SIZE], *encrypted_data;
	time_t timestamp;
    struct tm *calendar;
    time(&timestamp);
    calendar = localtime(&timestamp);
    char *new_filename = (char*) malloc(1024);
    long int filesize;

    // create new encryption file
	sprintf(new_filename, "./data/%d%d%d%d%d%d%s", calendar->tm_year, calendar->tm_mon, calendar->tm_mday, 
    calendar->tm_hour, calendar->tm_min, calendar->tm_sec, rindex(filelink, '.'));
    FILE *fp2 = fopen(new_filename, "wb+");

    // get file size
    fseek(fp1, 0, SEEK_END); // seek to end of file
    filesize = ftell(fp1); // get current file pointer
    fseek(fp1, 0, SEEK_SET); // seek back to beginning of file
    printf("Filesize: %ld\n", filesize);

	// file encryption
	while(filesize > 0){
		if(filesize > PAYLOAD_SIZE){
			fread(buff, PAYLOAD_SIZE, 1, fp1);
			encrypted_data = caesar_decryption(buff, key, PAYLOAD_SIZE);
			fwrite(encrypted_data, PAYLOAD_SIZE, 1, fp2);
			filesize -= PAYLOAD_SIZE;
		}else{
			// read the last block of file
			fread(buff, filesize, 1, fp1);
			encrypted_data = caesar_decryption(buff, key, filesize);
			fwrite(encrypted_data, filesize, 1, fp2);
			filesize = 0;
		}
		free(encrypted_data);
	}
	fclose(fp1);
	fclose(fp2);
	remove(filelink);

	return new_filename;
}