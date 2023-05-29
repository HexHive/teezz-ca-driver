CC = clang
INCLUDES = -I../include
CFLAGS = -target aarch64-linux-android21 -shared -g -ggdb -std=gnu11 -fPIC $(INCLUDES)

TARGET = tcpreload

.PHONY: all clean


all: $(TARGET)

clean: $(TARGET)
	$(RM) $^
