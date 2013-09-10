#include <linux/fcntl.h>
#include <linux/fanotify.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "watcher.h"

int main(int argc, char **argv)
{
	
}

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

	/* TODO: register signal handler */

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

w_status w_start(struct watcher *self)
{
	/* TODO: set signals to right value*/
	sigset_t mask, oldmask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	while(true) {
		sigsuspend(&oldmask);
	}

	sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

w_status w_shutdown(struct watcher *self)
{
	free(self->conf);
}

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
