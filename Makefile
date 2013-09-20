.PHONY: all clean

CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L

INCLUDES = `pkg-config --cflags libxml-2.0` `pkg-config --cflags glib-2.0`

LIBS = `pkg-config --libs libxml-2.0` `pkg-config --libs glib-2.0`

all: munin

munin: munin.c munin.h
	gcc  $(CFLAGS) $(INCLUDES)  -o munin munin.c $(LIBS)

rsync-test: rsync-test.c
	gcc $(CFLAGS) -o rsync-test rsync-test.c

clean:
	rm munin
	rm rsync-test

install: munin
	cp ./munin.conf /etc/munin.conf
	cp ./munin.start /etc/munin.start
	mkdir /var/lib/munin
	mv munin /usr/bin/

deinstall:
	rm /etc/munin.start
	rm /etc/munin.conf
	rm -r /var/lib/munin
	rm /usr/bin/munin

test: munin
	echo "0" > /etc/munin.start
	echo "/var/lib/munin/" > /etc/munin.path
	./munin --daemon

testend:
	rm /etc/munin.start
	pkill munin
	rm /var/lib/munin/save
