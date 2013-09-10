#include <linux/fcntl.h>
#include <linux/fanotify.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <sys/poll.h>

#include "watcher.h"

int main(int argc, char **argv)
{
	
}

/*
  function, which initializes the daemon. It ensures, that there is only
  one daemon running in the system. It then forks the daemon in the background.

  @self:  pointer to the own data structure
  @return: returns, if the starting of the daemon was successful.
 */

w_status w_init(struct watcher *self)
{
	w_status res = FAILURE;
	char *confname = "/etc/watcher.conf";
	struct passwd pwd;
	struct passwd *result;
	struct w_config *conf;
	int retval = 0;
	char buf[MAX_CMD];
	char *cmd_buf;
	xmlDocPtr doc;


	errno  = 0;
	conf = malloc(sizeof(struct w_config));
	if (!conf) {
		fprintf(stderr, "No memory left. Program will shut down now.\n");
		exit(EXIT_FAILURE);
	}

	doc = read_config(confname, conf);
	if (!doc) {
		fprintf(stderr, "Please contact your local system administrator\n");
		exit(EXIT_FAILURE);
	} else {
		xmlSaveFormatFile (confname, doc, 0);
		xmlFreeDoc(doc);
	}

	size_t bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (!bufsize) {
		bufsize = DEFAULT_BUFFER_SIZE;
	}

	char *buff = malloc(bufsize);
	if (buff != NULL) {
		int s = getpwnam_r("daemon", &pwd, buff, bufsize, &result);

		if (s == 0 && result) {
			setuid(result->pw_uid);
		}
		free(buff);
	} else {
		fprintf(stderr, "No memory left. Program will shut down now.\n");
		exit(EXIT_FAILURE);
	}

	if((pid = fork()) < 0) {
		exit(EXIT_FAILURE);
	} else if(pid != 0) {
		exit(EXIT_SUCCESS);
	}

	umask(077);

	sid = setsid();

	if(sid < 0) {
		fprintf(stderr, "failed to change sid\n");
		exit(EXIT_FAILURE);
	}

	/* double-fork pattern to prevent zombie children */
	if((pid = fork()) < 0) {
		exit(EXIT_FAILURE);
	} else if(pid != 0) {
		/* parent */
		exit(EXIT_SUCCESS);
	}

	if (-1 == chdir(conf->wd)) {
		perror("could not change into working directory");
		exit(EXIT_FAILURE);
	}
	self->conf = conf;

	openlog("watcher", LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);

	res = SUCCESS;
	return res;
}
/*
  function, which implements the main loop of the daemon.
  It initializes fanotify and the internal hashmap, which saves the names of
  the changed files. It then registers the events in the filesystem, which
  change files. These are stored in the hashmap.

  @self: pointer to the own data structure
  @return: returns, if there occured an error
 */
w_status w_start(struct watcher *self)
{
        struct pollfd pollfd[_FD_MAX] = {};
        Hashmap *files = NULL;
	char *p;


        files = hashmap_new(string_hash_func, string_compare_func);
        if (!files) {
                syslog(LOG_ERR, "Failed to allocate set: %m");
                goto finish;
        }

        fanotify_fd = fanotify_init(FAN_CLOEXEC|FAN_NONBLOCK, O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_NOATIME);
        if (fanotify_fd < 0) {
                syslog(LOG_ERR, "Failed to create fanotify object: %m");
                goto finish;
        }

	pollfd[0].fd = fanotify_fd;
	pollfd[0].events = POLLIN;

        if (fanotify_mark(fanotify_fd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_MODIFY, AT_FDCWD, "/") < 0) {
                syslog(LOG_ERR, "Failed to mark /: %m");
                goto finish;
        }

	while(1) {
                union {
                        struct fanotify_event_metadata metadata;
                        char buffer[4096];
                } data;
                struct fanotify_event_metadata *m;
                ssize_t n;

		if ((h = poll(pollfd, _FD_MAX, -1))) {
			if (errno == EINTR)
				continue;

			syslog(LOG_ERR, "poll(): %m");
			goto finish;
		}
                if ((n = read(fanotify_fd, &data, sizeof(data))) < 0) {

                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        if (errno == EACCES)
                                continue;

                        syslog(LOG_ERR, "Failed to read event: %m");
                        goto finish;
                }
                for (m = &data.metadata; FAN_EVENT_OK(m, n); m = FAN_EVENT_NEXT(m, n)) {
                        char fn[PATH_MAX];

                        if (m->fd < 0)
                                goto next_iteration;

                        if (m->pid == getpid())
                                goto next_iteration;

                        snprintf(fn, sizeof(fn), "/proc/self/fd/%i", m->fd);
			fn[sizeof(fn) - 1] = 0;

                        if ((k = readlink_malloc(fn, &p)) >= 0) {
                                if (endswith(p, " (deleted)") ||
                                    hashmap_get(files, p))
                                        free(p);
                                else {
                                        struct item *entry;

                                        entry = (struct item *) calloc(1,sizeof(struct item));
                                        if (!entry) {
						syslog(LOG_ERR,
						       "could not create map item: Out of Memory");
                                                r = FAILURE;
                                                goto finish;
                                        }

                                        entry->path = strdup(p);
                                        if (!entry->path) {
                                                free(entry);
						syslog(LOG_ERR,
						       "could not copy path: Out of Memory");

                                                r = FAILURE;
                                                goto finish;
                                        }

                                        k = hashmap_put(files, p, entry);
                                        if (k < 0) {
                                                syslog(LOG_WARNING"hashmap_put() failed: %s", strerror(-k));
                                                free(p);
                                        }
				}
			}
		}

	}

 finish:

}
/*
  Helper function, that will extract the filename out of the
  given file descriptor. Function taken from systemd.
 */

int readlink_malloc(const char *p, char **r) {
        size_t l = 100;

        for (;;) {
                char *c;
                ssize_t n;

                if (!(c = (char *) malloc(sizeof(char) * l))))
                        return -ENOMEM;

                if ((n = readlink(p, c, l-1)) < 0) {
                        int ret = -errno;
                        free(c);
                        return ret;
                }

                if ((size_t) n < l-1) {
                        c[n] = 0;
                        *r = c;
                        return 0;
                }

                free(c);
                l *= 2;
        }
}
/*
  function called, when daemon is shut down. This function will write the
  current hashmap to the disc and cleans up all the used variables.

  @self: pointer to the own data structure
  @return: returns, if the shutdown is correctly executed.
 */

w_status w_shutdown(struct watcher *self)
{
	/* TODO: Write the current hash map to the disc
	   Note: save, if the daemon is shut down successfully
	 */

	free(self->conf->wd);
	free(self->conf);
}

/*
  parses the config file and changes the value of the config variable.

  Note: Only valid config files can be parsed. If unsure, what keys can be
  set, you should look at the default config file.

  @confname: name of the config file. Default: /etc/watcher.c
  @keyname: name of the config variable.
  @value: value, which shall be set for the config variable keyname
  @return: returns a pointer to the parsed xml config file
 */

xmlDocPtr write_config(char *confname, char *keyname, char *value)
{
	xmlDocPtr doc;
	xmlNodePtr cur;

	doc = xmlParseFile(confname);

	if (doc == NULL ) {
		fprintf(stderr,"Document not parsed successfully. \n");
		return (NULL);
	}

	cur = xmlDocGetRootElement(doc);

	if (cur == NULL) {
		fprintf(stderr,"empty document\n");
		xmlFreeDoc(doc);
		return (NULL);
	}

	if (xmlStrcmp(cur->name, (const xmlChar *) "config")) {
		fprintf(stderr,"document of the wrong type, root node != config");
		xmlFreeDoc(doc);
		return (NULL);
	}

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *) keyname))){
			xmlNodeSetContent(cur->xmlChildrenNode, value);
		}

		cur = cur->next;
	}
return(doc);
}

/*
  parses the config file and sets the config values for the daemon.

  Note: Only valid config files can be parsed. If unsure, what keys can be
  set, you should look at the default config file.

  @confname: name of the config file. Default: /etc/watcher.conf
  @conf: pointer to the config structure used by the daemon
  @return: returns a pointer to the parsed xml config file
 */
xmlDocPtr read_config(char *confname, w_conf *conf)
{
	xmlDocPtr doc;
	xmlNodePtr cur;
	xmlChar *tmp;

	doc = xmlParseFile(confname);

	if (doc == NULL ) {
		fprintf(stderr,"Document not parsed successfully. \n");
		return (NULL);
	}

	cur = xmlDocGetRootElement(doc);

	if (cur == NULL) {
		fprintf(stderr,"empty document\n");
		xmlFreeDoc(doc);
		return (NULL);
	}

	if (xmlStrcmp(cur->name, (const xmlChar *) "config")) {
		fprintf(stderr,"document of the wrong type, root node != config");
		xmlFreeDoc(doc);
		return (NULL);
	}

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *) "working_directory"))){
			tmp = xmlNodeGetContent(cur->xmlChildrenNode);
			strcpy(conf->wd, (const char *) tmp);
			xmlFree(tmp);
		}

		cur = cur->next;
	}
	return(doc);
}
