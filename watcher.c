#include <linux/fcntl.h>
#include <sys/fanotify.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <poll.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <limits.h>
#include <glib.h>

#include "watcher.h"

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
	pid_t pid;
	pid_t sid;
	size_t bufsize;
	char *buff;
	int s;

	errno  = 0;
	conf = malloc(sizeof(struct w_config));
	if (!conf) {
		fprintf(stderr, "No memory left. Program will shut down now.\n");
		return res;
	}

	doc = read_config(confname, conf);
	if (!doc) {
		fprintf(stderr, "Please contact your local system administrator\n");
		return res;
	} else {
		xmlSaveFormatFile (confname, doc, 0);
		xmlFreeDoc(doc);
	}

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (!bufsize) {
		bufsize = DEFAULT_BUFFER_SIZE;
	}

	buff = malloc(bufsize);
	if (buff != NULL) {
		s = getpwnam_r("daemon", &pwd, buff, bufsize, &result);

		if (s == 0 && result) {
			setuid(result->pw_uid);
		}
		free(buff);
	} else {
		fprintf(stderr, "No memory left. Program will shut down now.\n");
		return res;
	}

	if((pid = fork()) < 0) {
		return res;
	} else if(pid != 0) {
		exit(EXIT_SUCCESS);
	}

	umask(077);

	sid = setsid();

	if(sid < 0) {
		fprintf(stderr, "failed to change sid\n");
		return res;
	}

	/* double-fork pattern to prevent zombie children */
	if((pid = fork()) < 0) {
		return res;
	} else if(pid != 0) {
		/* parent */
		exit(EXIT_SUCCESS);
	}

	if (-1 == chdir(conf->wd)) {
		perror("could not change into working directory");
		return res;
	}
	self->conf = conf;

	openlog("watcher", LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);

	res = SUCCESS;
	return res;
}

int endswith(char path[], const char *needle)
{
	char *pos;
	size_t len;
	
	pos = strstr(path, needle);
	len = strlen(path);

	if (pos) {
		if (pos == &path[len - 11]) {
			return 1;
		}
	}

	return -1;
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
        struct pollfd pollfd[2] = {};
        GHashTable *files = NULL;
	char *p;
	int fanotify_fd;
	int h;
	int k;
	ssize_t n;
	w_status r;

        files = g_hash_table_new(g_str_hash, g_str_equal);
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

		if ((h = poll(pollfd, 2, -1))) {
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
				continue;

                        if (m->pid == getpid())
				continue;

                        snprintf(fn, sizeof(fn), "/proc/self/fd/%i", m->fd);
			fn[sizeof(fn) - 1] = 0;

                        if ((k = readlink_malloc(fn, &p)) >= 0) {
                                if (endswith(p, " (deleted)") < 0 || g_hash_table_lookup(files, p))
                                        free(p);
                                else {
                                        struct item *entry;

					/* TODO: FREE */
                                        entry = (struct item *) calloc(1, sizeof(struct item));
                                        if (!entry) {
						syslog(LOG_ERR,
						       "could not create map item: Out of Memory");
                                                r = FAILURE;
						free(p);
                                                goto finish;
                                        }

					/* TODO: FREE */
                                        entry->path = malloc(strlen(p) + 1);
                                        if (!entry->path) {
                                                free(entry);
						free(p);
						syslog(LOG_ERR,
						       "could not copy path: Out of Memory");

                                                r = FAILURE;
                                                goto finish;
                                        }
					strncpy(entry->path, p, strlen(p) + 1);

                                        g_hash_table_insert(files, p, entry);
				}
			}
		}

	}

 finish:
	return r;
}

/*
  Helper function, that will extract the filename out of the
  given file descriptor. Function taken from systemd.
 */

int readlink_malloc(const char *p, char **r)
{
        size_t l = 100;
	char *c;
	ssize_t n;

        for (;;) {
                if (!(c = (char *) malloc(sizeof(char) * l)))
                        return -ENOMEM;

                if ((n = readlink(p, c, l-1)) < 0) {
                        free(c);
                        return -errno;
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
xmlDocPtr read_config(char *confname, struct w_config *conf)
{
	xmlDocPtr doc;
	xmlNodePtr cur;
	xmlChar *tmp;

	doc = xmlParseFile(confname);

	if (doc == NULL ) {
		fprintf(stderr,"Document not parsed successfully.\n");
		return NULL;
	}

	cur = xmlDocGetRootElement(doc);

	if (cur == NULL) {
		fprintf(stderr,"empty document\n");
		xmlFreeDoc(doc);
		return NULL;
	}

	if (xmlStrcmp(cur->name, (const xmlChar *) "config")) {
		fprintf(stderr,"document of the wrong type, root node != config\n");
		xmlFreeDoc(doc);
		return NULL;
	}

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *) "working_directory"))){
			tmp = xmlNodeGetContent(cur->xmlChildrenNode);
			conf->wd = malloc(strlen((const char *) tmp) + 1);
			if (!conf->wd) {
				fprintf(stderr, "Out of memory, program shutting down.\n");
				return NULL;
			}

			strcpy(conf->wd, (const char *) tmp);
			xmlFree(tmp);
		}

		cur = cur->next;
	}
	return(doc);
}

int main(int argc, char **argv)
{

}
