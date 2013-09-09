#include <linux/fanotify.h>

#include "watcher.h"

int main(int argc, char **argv)
{
	
}

w_status w_init(struct watcher *self)
{
	w_status res = FAILURE;
	FILE *config;
	struct passwd pwd;
	struct passwd *result;
	struct w_config *conf;
	int retval = 0;
	char buf[MAX_CMD];
	char *cmd_buf;


	errno  = 0;
	conf = malloc(sizeof(struct w_config));
	if (!conf) {
		fprintf(stderr, "No memory left. Program will shut down now.");
		exit(EXIT_FAILURE);
	}

	config = fopen("/etc/watcher.conf", "r");
	if (!config) {
		perror("Please contact your local system administrator");
		exit(EXIT_FAILURE);
	} else {
		/* TODO: read saved values */
		/* TODO: implement libxml*/
		if (!strcmp(buf, "working_directory")) {
			cmd_buf = malloc(PATH_MAX+1);
			if(!fgets(cmd_buf, PATH_MAX, config)) {
				fprintf(stderr,
					"working directory initialisation failed, going back to default");
				conf->wd = "/var/lib/watcher";
			}
		}
	}

	fclose(config);

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
		fprintf(stderr, "No memory left. Program will shut down now.");
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
		fprintf(stderr, "failed to change sid");
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
