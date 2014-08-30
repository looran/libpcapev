CFLAGS += -Wall -fPIC

PREFIX=/usr/local
INCLUDEDIR=$(PREFIX)/include
LIBDIR=$(PREFIX)/lib
LIBNAME=libpcapev

TARGET  = ${LIBNAME}.so
SOURCES = pcapev.c
HEADERS = pcapev.h
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -fPIC -shared -o $(TARGET) $(OBJECTS) -lpcap -levent

install:
	@echo "installation of $(LIBNAME)"
	mkdir -p $(LIBDIR)
	mkdir -p $(INCLUDEDIR)
	install -m 0644 $(TARGET) $(LIBDIR)
	install -m 0644 $(HEADERS) $(INCLUDEDIR)

clean:
	rm -f $(TARGET) $(OBJECTS)

