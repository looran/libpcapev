CFLAGS += -Wall -fPIC
PREFIX ?= /usr
INCLUDEDIR = $(DESTDIR)$(PREFIX)/include
LIBDIR  = $(DESTDIR)$(PREFIX)/lib
LIBNAME = libpcapev

TARGET_SHARED = ${LIBNAME}.so
TARGET_STATIC = ${LIBNAME}.a
SOURCES = pcapev.c
HEADERS = pcapev.h
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET_SHARED) $(TARGET_STATIC)

$(TARGET_SHARED): $(OBJECTS)
	$(CC) $(CFLAGS) -fPIC -shared -o $(TARGET_SHARED) $(OBJECTS) -lpcap -levent

$(TARGET_STATIC): $(OBJECTS)
	$(AR) rvs $(TARGET_STATIC) $(OBJECTS)

install:
	@echo "installation of $(LIBNAME)"
	mkdir -p $(LIBDIR)
	mkdir -p $(INCLUDEDIR)
	install -m 0644 $(TARGET_SHARED) $(LIBDIR)
	install -m 0644 $(TARGET_STATIC) $(LIBDIR)
	install -m 0644 $(HEADERS) $(INCLUDEDIR)

clean:
	rm -f $(TARGET_SHARED) $(TARGET_STATIC) $(OBJECTS)

