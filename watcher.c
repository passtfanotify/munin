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
 * This function initializes the daemon. It ensures, that there is only
 * one daemon running in the system. It then forks the daemon in the background.
 *
 * @self:  pointer to the own data structure
 * @return: returns, if the starting of the daemon was successful.
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
	FILE *sfile;
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
		s = getpwnam_r("root", &pwd, buff, bufsize, &result);

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
	if((pid = fork()) < 0) {
		return res;
	} else if(pid != 0) {
		exit(EXIT_SUCCESS);
	}
	sfile = fopen("/etc/watcher.start", "w");
	if (!sfile) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	fprintf(sfile, "s%i\0", getpid());
	fclose(sfile);

	if (-1 == chdir(conf->wd)) {
		perror("could not change into working directory");
		free(conf);
		return res;
	}
	self->conf = conf;

	remove("/etc/watcher.path");
	FILE *wdpath = fopen("/etc/watcher.path", "w");
	if (!wdpath) {
		fprintf(stderr,"error opening conffile to write: %m");
	}
	fprintf(wdpath, "%s", self->conf->wd);
	fclose(wdpath);


	openlog("watcher", LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);

	save = fopen("save", "r");
	if(!save) {
		res = SUCCESS;
		return res;
	}

	while(fgets(input, PATH_MAX, save)){
		struct item *entry;

		entry = (struct item *) calloc(1, sizeof(struct item));
		if (!entry) {
			syslog(LOG_ERR,
			       "could not create map item: Out of Memory");
			free(p);
			return res;
		}
		input[strlen(input)-1] = '\0';

		p = malloc((strlen(input) + 1 )* sizeof(char));
		if (!p) {
			syslog(LOG_ERR,
			       "could not copy path: Out of Memory");

			return res;
		}

		strcpy(p, input);

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

	if (ferror(save)) {
		return res;
	}

	remove("save");
	res = SUCCESS;
	return res;
}

/*
 * Helper function, that checks if an string ends with the
 * string 'needle'
 */
int endswith(char path[], const char *needle)
{
	char *pos;
	size_t len;
	size_t needle_len;

	pos = strstr(path, needle);
	len = strlen(path);
	needle_len = strlen(needle);

	if (pos) {
		if (pos == &path[len - needle_len]) {
			return 1;
		}
	}

	return -1;

}

/*
 * Helper function, that checks if an string starts with the
 * string 'needle'
 */
int startswith(char path[], const char *needle){
	char *pos;
	size_t len;
	size_t needle_len;

	pos = strstr(path, needle);
	len = strlen(path);
	needle_len = strlen(needle);

	if (pos) {
		if (pos == &path[0]) {
			return 1;
		}
	}

	return -1;

}


/*
 * This function implements the main loop of the daemon.
 * It initializes fanotify and the internal hashmap, which saves the names of
 * the changed files. It then registers the events in the filesystem, which
 * change files. These are stored in the hashmap.
 *
 * @self: pointer to the own data structure
 * @return: returns, if there occured an error
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

	sigprocmask(SIG_BLOCK, &mask, NULL);

        if ((signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0) {
                syslog(LOG_ERR,"Failed to get signal fd: %m");
        	return res;
        }



	pollfd[0].fd = fanotify_fd;
	pollfd[0].events = POLLIN;
	pollfd[1].fd = signal_fd;
	pollfd[1].events = POLLIN;

	for(i=0; i< self->conf->monitor_count; i++){
		if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD, self->conf->monitor_paths[i]) < 0) {
			syslog(LOG_ERR, "Failed to mark %s: %m", self->conf->monitor_paths[i]);
        		return res;
		}
	}

	while(1) {
		union {
                        struct fanotify_event_metadata metadata;
                } data;
                struct fanotify_event_metadata *m;
                ssize_t n;
		struct signalfd_siginfo sigs;
		void **thread_res;

		errno = 0;

		if ((h = poll(pollfd, 2, -1)) == -1) {
			if (errno == EINTR)
				continue;

			syslog(LOG_ERR, "poll failed: %m");
        		return res;
		}

                if (pollfd[1].revents) {
			if(read(signal_fd, &sigs, sizeof(sigs)) < 0) {
				if (errno == EINTR || errno == EAGAIN)
					continue;

				if (errno == EACCES)
					continue;

				syslog(LOG_ERR, "Failed to read signal: %m");
        			return res;
			}
			close(sigs.ssi_fd);
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
				self->act_caller = sigs.ssi_pid;
				pthread_create(&self->thread_output, NULL, output, self);
				continue;
			} else {
				res = SUCCESS;
				return res;
			}
                }

                if ((n = read(fanotify_fd, &data, sizeof(data))) < 0) {

                        if (errno == EINTR || errno == EAGAIN) {
                                continue;
			}

                        if (errno == EACCES)
                                continue;

                        syslog(LOG_ERR, "Failed to read event: %m");
        		return res;
                }

                for (m = &data.metadata; FAN_EVENT_OK(m, n); m = FAN_EVENT_NEXT(m, n)) {
                        char fn[PATH_MAX];

                        if (m->fd < 0)
				continue;

                        if (m->pid == getpid()) {
				close(m->fd);
				continue;
			}

                        snprintf(fn, sizeof(fn), "/proc/self/fd/%i", m->fd);
			fn[sizeof(fn) - 1] = '\0';

                        if ((k = readlink_malloc(fn, &p)) >= 0) {
				int z;
				int ignore = 1;
				for(z  = 0; z < self->conf->monitor_count; z++) {
					if (startswith(p, self->conf->monitor_paths[z]) == 1) {
						ignore = 0;
						break;
					}
				}
                                if (ignore || endswith(p, " (deleted)") == 1|| g_hash_table_lookup(self->files, p)) {
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
					strcpy(entry->path, p);

                                        g_hash_table_insert(self->files, p, entry);
				}
			}
			close(m->fd);
		}

	}
}

/*
 * Helper function, that will extract the filename out of the
 * given file descriptor. Function taken from systemd.
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
 * This function called, when daemon is shut down. This function will write the
 * current hashmap to the disc and cleans up all the used variables.
 *
 * @self: pointer to the own data structure
 * @return: return an status, if the config change was successful
 */
w_status w_shutdown(struct watcher *self)
{
	int k = 0;
	FILE *savefile = fopen("save", "w+");

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

	g_hash_table_destroy(self->files);
	g_hash_table_destroy(self->old_files);

	free(self->conf->wd);
	for(k=0; k < self->conf->monitor_count; k++){
		free(self->conf->monitor_paths[k]);
	}
	free(self->conf->monitor_paths);
	free(self->conf);

	return SUCCESS;
}

/*
 * This function parses the config file and changes the value of the
 * config variable.
 *
 * Note: Only valid config files can be parsed. If unsure, what keys
 *       can be set, you should look at the default config file.
 *
 * @confname: name of the config file. Default: /etc/watcher.conf
 * @keyname: name of the config variable.
 * @value: value, which shall be set for the config variable keyname
 * @return: returns a pointer to the parsed xml config file
 */
xmlDocPtr write_config(char *confname, char *keyname, char *value, int pid, int mode)
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
				if(mode == 1){
					name = malloc(strlen("value") + 1);
					sprintf(name, "value");
					child = xmlNewChild(cur, NULL, name, value);
					xmlNewProp(child, "changed", "1");
					xmlSetProp(cur, "changed", "1");
					child->next = xmlNewText("\n  ");
				} else {
					child = cur->xmlChildrenNode;
					child = child->next;
					while (child != NULL) {
						if (!xmlStrcmp(xmlNodeGetContent(child), (const xmlChar *) value)) {
							break;
						}
						child = child->next;
						child = child->next;
					}
					xmlSetProp(cur, "changed", "1");
					xmlSetProp(child, "changed", "2");
				}
			} else {
				fprintf(stderr, "changing wd started\n");
				child = cur->xmlChildrenNode;
				child = child->next;
				xmlNodeSetContent(child, value);
				xmlSetProp(cur, "changed", "1");
				fprintf(stderr, "changing wd ended\n");
			}
		}

		cur = cur->next;
	}
	remove("/etc/watcher.conf");
	FILE *conffile = fopen("/etc/watcher.conf", "w+");
	if (!conffile) {
		fprintf(stderr,"error opening conffile to write: %m");
	}
	xmlDocDump(conffile, doc);

	kill(pid, SIGUSR1);

	return(doc);
}

/*
 * parses the config file and sets the config values for the daemon.
 *
 * Note: Only valid config files can be parsed. If unsure, what keys can be
 *       set, you should look at the default config file.
 *
 * @confname: name of the config file. Default: /etc/watcher.conf
 * @conf: pointer to the config structure used by the daemon
 * @return: returns a pointer to the parsed xml config file
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
			cur_path = cur->xmlChildrenNode;
			cur_path = cur_path->next;

			tmp = xmlNodeGetContent(cur_path);

			conf->wd = malloc(strlen((const char *) tmp) + 1);
			if (!conf->wd) {
				fprintf(stderr, "Out of memory, program shutting down.\n");
				return NULL;
			}

			strcpy(conf->wd, (const char *) tmp);
			xmlFree(tmp);
		} else if ((!xmlStrcmp(cur->name, (const xmlChar *) "monitor_paths"))) {
			cur_path = cur->xmlChildrenNode;
			cur_path = cur_path->next;

			conf->monitor_count = xmlChildElementCount(cur);

			conf->monitor_paths = malloc(conf->monitor_count * sizeof(char *));

			int k = 0;
			while(cur_path != NULL) {
				tmp = xmlNodeGetContent(cur_path);

				conf->monitor_paths[k] = malloc(strlen((const char *) tmp) + 1);
				if (!conf->monitor_paths[k]) {
					fprintf(stderr, "Out of memory, program shutting down.\n");
					return NULL;
				}
				strcpy(conf->monitor_paths[k], (const char *) tmp);

				xmlFree(tmp);

				k++;
				cur_path = cur_path->next;

				if (cur_path == NULL) {
					break;
				}
				cur_path = cur_path->next;
			}
		}

		cur = cur->next;
	}

	return(doc);
}

/*
 * The main function handles the call of the daemon. It handles
 * the input parameters and starts the corresponding action.
 *
 * Note: The use of the --daemon option can lead to undefined
 *       behavior, when used in combination with the other
 *       parameters
 */
int main(int argc, char **argv)
{
	struct watcher *self;
	w_status res;
	FILE *sfile;
	time_t stime;
	char tmp;
	size_t readsize;
	int daemon = 0;
	int i;
	char *confname = "/etc/watcher.conf";
	char dpid[sizeof(pid_t)];
	int started = 0;
	pid_t spid;

	if (!strcmp(argv[1], "--help")) {
		printf("Usage: %s [--daemon] OR %s [--dir <working_dir>] [--addpath <watch_path>]  [--removepath <watched_path>]", argv[0], argv[0]);
		exit(EXIT_SUCCESS);
	}

	sfile = fopen("/etc/watcher.start", "r");
	if (!sfile) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	readsize = fread(&tmp, 1, 1, sfile);

	if (readsize != 1) {
		fprintf(stderr, "Read of /etc/watcher.start failed");
		fclose(sfile);
		exit(EXIT_FAILURE);
	}

	if (tmp == 's') {
		started = 1;
		fread(dpid, sizeof(pid_t), 1, sfile);
	}

	fclose(sfile);

	if (!strcmp(argv[1], "--daemon")) {
		daemon = 1;
	}

	spid = (pid_t) atoi(dpid);

	if (started == 1 && daemon == 0) {
		for (i = 1; i < argc; i++) {

			if (!strcmp(argv[i], "--dir")) {
				if (argv[++i]) {
					write_config(confname, "working_directory", argv[i], spid, 0);
					i++;
				}
				continue;
			}

			if (!strcmp(argv[i], "--addpath")) {
				if (argv[++i]) {
					write_config(confname, "monitor_paths", argv[i], spid, 1);
					i++;
				}
				continue;

			}

			if (!strcmp(argv[i], "--removepath")) {
				if (argv[++i]) {
					write_config(confname, "monitor_paths", argv[i], spid, 0);
					i++;
				}
				continue;
			}
		}

	} else if (daemon == 1) {
		sfile = fopen("/etc/watcher.start", "w");
		if (!sfile) {
			perror("fopen");
			exit(EXIT_FAILURE);
		}

		fprintf(sfile, "s\0", getpid());
		fclose(sfile);
		self = malloc(sizeof(struct watcher));

		if(!self) {
			fprintf(stderr, "Out of memory. Aborting.\n");
			exit(EXIT_FAILURE);
		}

		if (started == 1) {
			syslog(LOG_WARNING, "Program crashed last time. ");
			self->crash = 1;
		} else {
			self->crash = 0;
		}

		self->completed_out = 1;
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

		fprintf(sfile, "%i", (int) stime);
		fclose(sfile);
		exit(EXIT_SUCCESS);
	}
}
/*
 * This function changes the internal config structure,
 * that saves the config options, while the daemon is
 * running. The function is called, when SIGUSR1 is send
 * from the main method to the running daemon.
 *
 * @self: pointer to the own data structure
 * @fanotify_fd: file descriptor of fanotify
 * @return: return an status, if the config change was
 *          successful
 */
w_status change_conf(struct watcher *self, int fanotify_fd)
{
	xmlDocPtr doc;
	xmlNodePtr cur;
	xmlNodePtr cur_path;
	xmlNodePtr cur_delete;
	xmlChar *tmp;

	doc = xmlParseFile("/etc/watcher.conf");
	if (doc == NULL ) {
		syslog(LOG_ERR,"Document not parsed successfully.\n");
		return FAILURE;
	}

	cur = xmlDocGetRootElement(doc);
	if (cur == NULL) {
		syslog(LOG_ERR,"empty document\n");
		xmlFreeDoc(doc);
		return FAILURE;
	}

	if (xmlStrcmp(cur->name, (const xmlChar *) "config")) {
		syslog(LOG_ERR,"document of the wrong type, root node != config\n");
		xmlFreeDoc(doc);
		return FAILURE;
	}

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *) "working_directory")) && 
		    (!xmlStrcmp("1", xmlGetProp(cur, "changed")))){

			xmlSetProp(cur, "changed", "0");

			cur_path = cur->xmlChildrenNode;
			cur_path = cur_path->next;

			tmp = xmlNodeGetContent(cur_path);

			self->conf->wd = malloc(strlen((const char *) tmp) + 1);
			if (!self->conf->wd) {
				syslog(LOG_ERR, "Out of memory, program shutting down.\n");
				return FAILURE;
			}

			strcpy(self->conf->wd, (const char *) tmp);
			xmlFree(tmp);

			chdir(self->conf->wd);

			remove("/etc/watcher.path");
			FILE *wdpath = fopen("/etc/watcher.path", "w");
			if (!wdpath) {
				fprintf(stderr,"error opening conffile to write: %m");
			}
			fprintf(wdpath, "%s", self->conf->wd);
			fclose(wdpath);

		} else if ((!xmlStrcmp(cur->name, (const xmlChar *) "monitor_paths")) &&
			   (!xmlStrcmp("1", xmlGetProp(cur, "changed")))) {

			xmlSetProp(cur, "changed", "0");

			int k;
			cur_path = cur->xmlChildrenNode;
			cur_path = cur_path->next;
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
					syslog(LOG_ERR, "Out of memory, program shutting down.\n");
					return FAILURE;
				}

				strcpy(self->conf->monitor_paths[k], tmp);
				xmlFree(tmp);

				if (!xmlStrcmp("1", xmlGetProp(cur_path, "changed"))) {
					xmlSetProp(cur_path, "changed", "0");

					if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD, xmlNodeGetContent(cur_path)) < 0) {
						syslog(LOG_ERR, "Failed to mark %s: %m", xmlNodeGetContent(cur_path));
						return FAILURE;
					}
					cur_path = cur_path->next;
					if (cur_path != NULL)
						cur_path = cur_path->next;

				} else if (!xmlStrcmp("2", xmlGetProp(cur_path, "changed"))) {

					if (fanotify_mark(fanotify_fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT , FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD, xmlNodeGetContent(cur_path)) < 0) {
						syslog(LOG_ERR, "Failed to mark %s: %m", xmlNodeGetContent(cur_path));
						return FAILURE;
					}

					cur_delete = cur_path;
					cur_path = cur_path->next;
					xmlUnlinkNode(cur_delete);
					xmlFreeNode(cur_delete);

					if (cur_path != NULL) {
						cur_delete = cur_path;
						cur_path = cur_path->next;

					}

					xmlUnlinkNode(cur_delete);
					xmlFreeNode(cur_delete);

				} else {
					cur_path = cur_path->next;
					if (cur_path != NULL)
						cur_path = cur_path->next;

				}

				k++;
			}
		}

		cur = cur->next;
	}
	remove("/etc/watcher.conf");
	FILE *conffile = fopen("/etc/watcher.conf", "w+");
	if (!conffile) {
		fprintf(stderr,"error opening conffile to write: %m");
	}
	xmlDocDump(conffile, doc);

	return SUCCESS;

}

/*
 * This function handles the output of our internal hash structure.
 * It runs in an extra thread, that is started, when SIGUSR2 was
 * send from the backup software
 *
 * @watcher: pointer to the own data structure
 */
void *output(void *watcher)
{
	GHashTableIter iter;
	gpointer key, value;
	int res;
	struct watcher *self = (struct watcher *)watcher;
	self->completed_out = 0;

	remove("output");
	FILE *savefile = fopen("output", "w+");
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
	if (self->crash) {
		kill(self->act_caller, SIGUSR2);
	} else {
		kill(self->act_caller, SIGUSR1);
	}
	pthread_exit((void *)&res);
}
