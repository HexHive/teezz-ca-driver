CC = clang #aarch64-linux-android-gcc
INCLUDES = -I../include -I../libldteec/include
LIBS = -ldl
CFLAGS = -target aarch64-linux-android21 -ggdb -std=gnu11 -pie $(INCLUDES)

TARGET = secure_storage
SRC = secure_storage.c ../libldteec/libldteec.c
.PHONY: all clean

all: $(TARGET)

secure_storage: $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) -o $@ $^

clean: $(TARGET)
	$(RM) $^
