CC=gcc
CFLAGS=-Wall -Wextra -std=c11
TARGET=EncryptionApp
LDFLAGS=-lssl -lcrypto
SRC=EncryptionApp.c SHA3_test.c
OBJ=$(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)

