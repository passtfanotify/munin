.PHONY: all clean

all: watcher

watcher: watcher.c watcher.h
	gcc watcher.c -std=c99 -D_POSIX_C_SOURCE=200112L -I/usr/include/libxml2 -lxml2 -o watcher

clean:
	rm watcher
