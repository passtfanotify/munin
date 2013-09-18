#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/signal.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int sigvar = 0;


void start_backup(int sig) {
	sigvar = 1;
}


int main(int argc, char **argv)
{
	FILE *sfile;
	char dpid[10];
	char tmp;
	pid_t spid;
	char *input;
	char *output;
	int retval;
	char wd[PATH_MAX];
	size_t readsize;
	char *outfile;
	char *rargs[5];
	int *sig;
	struct sigaction action;

	if (argc != 3) {
		fprintf(stderr, "Wrong number of arguments!\n");
		exit(EXIT_FAILURE);
	}

	action.sa_handler = start_backup;
	retval = sigemptyset(&action.sa_mask);
	if (retval != 0) {
                fprintf(stderr, "sigemptyset failed.\n");
                exit(EXIT_FAILURE);
        }	
	//action.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &action, NULL);

	input = argv[1];
	output = argv[2];

	sfile = fopen("/etc/watcher.start", "r");
	if (!sfile) {
                perror("fopen");
                exit(EXIT_FAILURE);
        }

	readsize = fread(&tmp, 1, 1, sfile);
	if (readsize != 1) {
                fprintf(stderr, "Read of /etc/watcher.start failed\n");
                fclose(sfile);
                exit(EXIT_FAILURE);
        }

	if (tmp != 's') {
		fprintf(stderr, "Daemon not started. Start it first.\n");
		fclose(sfile);
		exit(EXIT_FAILURE);
	}

	fread(dpid, 10, 1, sfile);
	fclose(sfile);

	spid = (pid_t) atoi(dpid);
	
	retval = kill(spid, SIGUSR2);
	if (retval != 0) {
		perror("kill");
		exit(EXIT_FAILURE);
	}
	
	while(sigvar != 1) {

	}

	sfile = fopen("/etc/watcher.path", "r");
	if (!sfile) {
                perror("fopen");
                exit(EXIT_FAILURE);
        }

	fread(wd, PATH_MAX, 1, sfile);
	outfile = malloc(sizeof(wd) + 7);
	strcpy(outfile, wd);
	strcat(outfile, "output");
	rargs[2] = malloc(sizeof(outfile) + 15);

	rargs[0] = "rsync";
	rargs[1] = "-brp";
	sprintf(rargs[2], "--files-from=%s", outfile);
	rargs[3] = input;
	rargs[4] = output;

	execv("/usr/bin/rsync", rargs);

	perror("execv");
	exit(EXIT_FAILURE);
}
