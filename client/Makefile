#define the C compiler to use
CC = gcc

# define any conpile-time flags
CFLAGS = -g -Wall

# define any directories containing header files other than /usr/include
#
INCLUDES = -I../lib

#define the C source files
SRCS = tcp_client.c

#define the C object files
OBJS = $(SRCS:.c=.o)

#define the executable files
MAIN = client

all: $(MAIN)
	@echo client has been compiled

$(MAIN): $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm *.o $(MAIN)