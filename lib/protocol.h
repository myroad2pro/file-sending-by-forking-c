#define PAYLOAD_SIZE 65335

typedef struct message{
	char opcode;
	int length;
	char payload[PAYLOAD_SIZE];
}message;
