.PHONY: all clean

CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L

INCLUDES = `pkg-config --cflags libxml-2.0` `pkg-config --cflags glib-2.0`

LIBS = `pkg-config --libs libxml-2.0` `pkg-config --libs glib-2.0`

all: watcher

watcher: watcher.c watcher.h
	gcc  $(CFLAGS) $(INCLUDES)  -o watcher watcher.c $(LIBS)

clean:
	rm watcher

install: watcher
	cp ./watcher.conf /etc/watcher.conf
	cp ./watcher.start /etc/watcher.start
	mkdir /var/lib/watcher

deinstall:
	rm /etc/watcher.start
	rm /etc/watcher.conf
	rm -r /var/lib/watcher

test: watcher
	echo "0" > /etc/watcher.start
	./watcher --daemon

testend:
	rm /etc/watcher.start
	pkill watcher
	rm /var/lib/watcher/save