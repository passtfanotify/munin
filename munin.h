#define MAX_CMD 18
#define DEFAULT_BUFFER_SIZE 1000

typedef enum {
	SUCCESS,
	FAILURE
} w_status;

struct w_config {
	char *wd;
	char **monitor_paths;
	int monitor_count;
};

struct item {
        char *path;
};

struct munin {
	/* sets parameters at start and forks the program */
	w_status (*init)(struct munin *self);
	/* starts the main loop */
	w_status (*start)(struct munin *self);

	/* clean up and remove daemon */
	w_status (*shutdown)(struct munin *self);

	struct w_config *conf;
	GHashTable *files;
	GHashTable *old_files;
	volatile int completed_out;
	pthread_t thread_output;
	int act_caller;
	int crash;
};

int readlink_malloc(const char *p, char **r);
w_status change_conf(struct munin *self, int fanotify_fd);
void *output(void *);
xmlDocPtr write_config(char *confname, char *keyname, char *value, int pid, int mode);
xmlDocPtr read_config(char *confname, struct w_config *conf);
w_status w_shutdown(struct munin *self);
