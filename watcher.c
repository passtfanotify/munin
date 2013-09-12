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
#include <signal.h>
#include <pthread.h>
#include <sys/signalfd.h>
#include <time.h>

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
	FILE *save;
	char input[PATH_MAX + 1];
	char *p;

	errno  = 0;
	conf = malloc(sizeof(struct w_config));
	if (!conf) {
		fprintf(stderr, "No memory left. Program will shut down now.\n");
		return res;
	}

	doc = read_config(confname, conf);
	if (!doc) {
		fprintf(stderr, "Please contact your local system administrator\n");
		free(conf);
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
		free(conf);
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
		free(conf);
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
		free(conf);
		return res;
	}
	self->conf = conf;

	openlog("watcher", LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);

	save = fopen("save", "r");

	while(fgets(input, PATH_MAX, save)){
		struct item *entry;

		entry = (struct item *) calloc(1, sizeof(struct item));
		if (!entry) {
			syslog(LOG_ERR,
			       "could not create map item: Out of Memory");
			free(p);
			return res;
		}

		p = malloc((strlen(input) + 1 )* sizeof(char));
		if (!p) {
			syslog(LOG_ERR,
			       "could not copy path: Out of Memory");

			return res;
		}

		strncpy(p, input, strlen(input) + 1);

		entry->path = malloc(strlen(p) + 1);
		if (!entry->path) {
			free(entry);
			free(p);
			syslog(LOG_ERR,
			       "could not copy path: Out of Memory");

			return res;
		}
		strncpy(entry->path, p, strlen(p) + 1);

		g_hash_table_insert(self->files, p, entry);

	}

	if (ferror(save))
		return res;

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
		if (pos == &path[len - 10]) {
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
	char *p;
	int fanotify_fd;
	int signal_fd;
	int h;
	int k;
	int i;
	ssize_t n;
	w_status res = FAILURE;
        sigset_t mask;
	GHashTable *tmp;

        fanotify_fd = fanotify_init(FAN_CLOEXEC|FAN_NONBLOCK, O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_NOATIME);
        if (fanotify_fd < 0) {
                syslog(LOG_ERR, "Failed to create fanotify object: %m");
        	return res;
	}
	sigemptyset(&mask);
        sigaddset(&mask, SIGUSR1);
        sigaddset(&mask, SIGUSR2);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGKILL);

        if ((signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0) {
                syslog(LOG_ERR,"Failed to get signal fd: %m");
        	return res;
        }



	pollfd[0].fd = fanotify_fd;
	pollfd[0].events = POLLIN;
	pollfd[1].fd = signal_fd;
	pollfd[1].events = POLLIN;

	for(i=0; i< self->conf->monitor_count; i++){
		if (fanotify_mark(fanotify_fd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_MODIFY, AT_FDCWD, (self->conf->monitor_paths[i])) < 0) {
			syslog(LOG_ERR, "Failed to mark %s: %m", self->conf->monitor_paths[i]);
        		return res;
		}
	}

	while(1) {
		union {
                        struct fanotify_event_metadata metadata;
                        char buffer[4096];
                } data;
                struct fanotify_event_metadata *m;
                ssize_t n;
		struct signalfd_siginfo sigs;
		void **thread_res;

		errno = 0;

		if ((h = poll(pollfd, 2, -1))) {
			if (errno == EINTR)
				continue;

			syslog(LOG_ERR, "poll failed: %m");
        		return res;
		}

                if (pollfd[1].revents) {
                        syslog(LOG_NOTICE, "Got signal");
			if(read(signal_fd, &sigs, sizeof(sigs)) < 0) {
				if (errno == EINTR || errno == EAGAIN)
					continue;

				if (errno == EACCES)
					continue;

				syslog(LOG_ERR, "Failed to read event: %m");
        			return res;
			}
			if (!self->completed_out && sigs.ssi_signo == SIGUSR1) {
				pthread_join(self->thread_output, thread_res);
				if (*((int *)(*thread_res)) == EXIT_FAILURE) {
					syslog(LOG_ERR, "output failed. exiting");
					return FAILURE;
				}
				change_conf(self, fanotify_fd);
				continue;
			} else if (!self->completed_out &&
				   (sigs.ssi_signo == SIGKILL || sigs.ssi_signo == SIGTERM)) {

				pthread_join(self->thread_output, thread_res);
				if (*((int *)(*thread_res)) == EXIT_FAILURE) {
					syslog(LOG_ERR, "output failed. exiting");
					return FAILURE;
				} else {
					w_shutdown(self);
					return SUCCESS;
				}
			} else if (sigs.ssi_signo == SIGUSR1){
				change_conf(self, fanotify_fd);
				continue;
			} else if (sigs.ssi_signo == SIGUSR2) {
				tmp = self->files;
				self->files = self->old_files;
				self->old_files = tmp;

				self->completed_out = 0;
				pthread_create(&self->thread_output, NULL, output, self);
				continue;
			} else {
				res = SUCCESS;
				return res;
			}
                }

                if ((n = read(fanotify_fd, &data, sizeof(data))) < 0) {

                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        if (errno == EACCES)
                                continue;

                        syslog(LOG_ERR, "Failed to read event: %m");
        		return res;
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
                                if (endswith(p, " (deleted)") < 0 || g_hash_table_lookup(self->files, p)) {
                                        free(p);
                                } else {
                                        struct item *entry;

                                        entry = (struct item *) calloc(1, sizeof(struct item));
                                        if (!entry) {
						syslog(LOG_ERR,
						       "could not create map item: Out of Memory");
						free(p);
        					return res;
                                        }

                                        entry->path = malloc(strlen(p) + 1);
                                        if (!entry->path) {
                                                free(entry);
						free(p);
						syslog(LOG_ERR,
						       "could not copy path: Out of Memory");

        					return res;
                                        }
					strncpy(entry->path, p, strlen(p) + 1);

                                        g_hash_table_insert(self->files, p, entry);
				}
			}
		}

	}
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
	int k = 0;
	FILE *savefile = fopen("save", "a+");

	GHashTableIter iter;
	gpointer key, value;

	if (!savefile) {
		return FAILURE;
	}

	g_hash_table_iter_init (&iter, self->files);
	while (g_hash_table_iter_next (&iter, &key, &value)){
		fprintf(savefile, "%s\n", (((struct item *)value)->path));
		free(key);
		free(((struct item *)value)->path);
		free(value);
		g_hash_table_iter_remove (&iter);
	}

	fclose(savefile);


	free(self->conf->wd);
	for(k=0; k < self->conf->monitor_count; k++){
		free(self->conf->monitor_paths[k]);
	}
	free(self->conf->monitor_paths);
	free(self->conf);

	return SUCCESS;
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

xmlDocPtr write_config(char *confname, char *keyname, char *value, int pid)
{
	xmlDocPtr doc;
	xmlNodePtr cur;
	xmlNodePtr child;
	char *name;

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
			if(strcmp(keyname, "monitor_paths") == 0) {
				name = malloc(strlen("value") + 3);
				sprintf(name, "value%d", (int) xmlChildElementCount(cur)+1);
				child = xmlNewChild(cur, NULL, name, value);
				xmlNewProp(child, "changed", "1");
				xmlSetProp(cur, "changed", "1");
			} else {
				xmlNodeSetContent(cur->xmlChildrenNode, value);
				xmlSetProp(cur, "changed", "1");
			}
		}

		cur = cur->next;
	}
	kill(pid, SIGUSR1);
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
	xmlNodePtr cur_path;
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
		} else if ((!xmlStrcmp(cur->name, (const xmlChar *) "monitor_paths"))) {
			cur_path = cur->xmlChildrenNode;
			conf->monitor_count = xmlChildElementCount(cur);
			conf->monitor_paths = malloc(conf->monitor_count * sizeof(char *));
			int k;
			while(cur_path != NULL) {
				tmp = xmlNodeGetContent(cur_path);
				conf->monitor_paths[k] = malloc(strlen((const char *) tmp) + 1);
				if (!conf->monitor_paths[k]) {
					fprintf(stderr, "Out of memory, program shutting down.\n");
					return NULL;
				}

				xmlFree(tmp);
				k++;
				cur_path = cur_path->next;
			}
		}

		cur = cur->next;
	}
	return(doc);
}

int main(int argc, char **argv)
{
	struct watcher *self;
	w_status res;
	FILE *sfile;
	time_t stime;
	char *tmp;
	size_t readsize;

	sfile = fopen("/etc/watcher.start", "r");
	if (!sfile) {
                perror("fopen");
                exit(EXIT_FAILURE);
        }

	readsize = fread(tmp, 1, 1, sfile);

	if (readsize != 1) {
		fprintf(stderr, "Read of /etc/watcher.start failed");
		exit(EXIT_FAILURE);
	}

	if (*tmp == '0') {
		/* TODO: Use traditional backup because of incorrect shutdown*/
		fclose(sfile);
	} else {

		rewind(sfile);
		fprintf(sfile, "0");
		fclose(sfile);
		self = malloc(sizeof(struct watcher));

		if(!self) {
			fprintf(stderr, "Out of memory. Aborting.\n");
			exit(EXIT_FAILURE);
		}

        	self->files = g_hash_table_new(g_str_hash, g_str_equal);
        	if (!self->files) {
                	fprintf(stderr,"Failed to allocate set: %m\n");
			free(self);
			exit(EXIT_FAILURE);
        	}

        	self->old_files = g_hash_table_new(g_str_hash, g_str_equal);
        	if (!self->old_files) {
                	fprintf(stderr, "Failed to allocate set: %m\n");
			g_hash_table_destroy(self->files);
			free(self);
			exit(EXIT_FAILURE);
        	}

		res = w_init(self);
		if (res == FAILURE) {
			fprintf(stderr, "Initialization of daemon failed.\n");
			g_hash_table_destroy(self->files);
			g_hash_table_destroy(self->old_files);
                	free(self);
			exit(EXIT_FAILURE);
		}

		res = w_start(self);
		if (res == FAILURE) {
			fprintf(stderr, "A runtime error occured. Please check logs.\n");
			g_hash_table_destroy(self->files);
			g_hash_table_destroy(self->old_files);
			free(self);
			exit(EXIT_FAILURE);
		}

		res = w_shutdown(self);
		if  (res == FAILURE) {
			exit(EXIT_FAILURE);
		}

		sfile = fopen("/etc/watcher.start", "w");
		if (!sfile) {
			perror("fopen");
			exit(EXIT_FAILURE);
		}

		stime = time(NULL);
		fprintf(sfile, "%s", ctime(&stime));
		fclose(sfile);
		exit(EXIT_SUCCESS);
	}
}

w_status change_conf(struct watcher *self, int fanotify_fd)
{
	xmlDocPtr doc;
	xmlNodePtr cur;
	xmlNodePtr cur_path;
	xmlChar *tmp;

	doc = xmlParseFile("/etc/watcher.conf");

	if (doc == NULL ) {
		fprintf(stderr,"Document not parsed successfully.\n");
		return FAILURE;
	}

	cur = xmlDocGetRootElement(doc);

	if (cur == NULL) {
		fprintf(stderr,"empty document\n");
		xmlFreeDoc(doc);
		return FAILURE;
	}

	if (xmlStrcmp(cur->name, (const xmlChar *) "config")) {
		fprintf(stderr,"document of the wrong type, root node != config\n");
		xmlFreeDoc(doc);
		return FAILURE;
	}

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *) "working_directory")) && 
		    (!xmlStrcmp("1", xmlGetProp(cur, "changed")))){

			tmp = xmlNodeGetContent(cur->xmlChildrenNode);
			self->conf->wd = malloc(strlen((const char *) tmp) + 1);
			if (!self->conf->wd) {
				fprintf(stderr, "Out of memory, program shutting down.\n");
				return FAILURE;
			}

			strcpy(self->conf->wd, (const char *) tmp);
			xmlFree(tmp);
			chdir(self->conf->wd);
		} else if ((!xmlStrcmp(cur->name, (const xmlChar *) "monitor_paths")) &&
			   (!xmlStrcmp("1", xmlGetProp(cur, "changed")))) {

			int k;
			cur_path = cur->xmlChildrenNode;
			for (k = 0; k < self->conf->monitor_count; k++) {
				free(self->conf->monitor_paths[k]);
			}
			free(self->conf->monitor_paths);

			self->conf->monitor_count = xmlChildElementCount(cur);
			self->conf->monitor_paths = malloc(self->conf->monitor_count * sizeof(char *));

			k = 0;
			while (cur_path != NULL) {
				tmp = xmlNodeGetContent(cur_path);
				self->conf->monitor_paths[k] = malloc(strlen((const char *) tmp) + 1);
				if (!self->conf->monitor_paths[k]) {
					fprintf(stderr, "Out of memory, program shutting down.\n");
					return FAILURE;
				}

				xmlFree(tmp);

				if (!xmlStrcmp("1", xmlGetProp(cur_path, "changed"))) {
					if (fanotify_mark(fanotify_fd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_MODIFY, AT_FDCWD, xmlNodeGetContent(cur_path)) < 0) {
						syslog(LOG_ERR, "Failed to mark %s: %m", xmlNodeGetContent(cur_path));
						return FAILURE;
					}
				}

				k++;
				cur_path = cur_path->next;
			}
		}

		cur = cur->next;
	}
	return SUCCESS;

}

void *output(void *watcher)
{
	FILE *savefile = fopen("output", "a+");

	GHashTableIter iter;
	gpointer key, value;
	int res;
	struct watcher *self = (struct watcher *)watcher;

	if (!savefile) {
		res = EXIT_FAILURE;
		self->completed_out = 1;
		pthread_exit((void *)&res);
	}

	g_hash_table_iter_init (&iter, self->old_files);
	while (g_hash_table_iter_next (&iter, &key, &value)){
		fprintf(savefile, "%s\n", (((struct item *)value)->path));
		free(key);
		free(((struct item *)value)->path);
		free(value);
		g_hash_table_iter_remove (&iter);
	}

	fclose(savefile);
	res = EXIT_SUCCESS;
	self->completed_out = 1;
	pthread_exit((void *)&res);
}
