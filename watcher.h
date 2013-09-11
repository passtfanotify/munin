#define MAX_CMD 18
#define DEFAULT_BUFFER_SIZE 1000

struct watcher get_instance(void);

typedef enum {
	SUCCESS,
	FAILURE
} w_status;

struct w_config {
	char *wd;
};

struct item {
        char *path;
};

struct watcher {
	/* sets parameters at start and forks the program */
	w_status (*init)(struct watcher *self);
	/* starts the main loop */
	w_status (*start)(struct watcher *self);

	/* change parameters of the daemon */
	w_status (*change_params)(struct watcher *self, char **argv);

	/* clean up and remove daemon */
	w_status (*shutdown)(struct watcher *self);

	struct w_config *conf;
	GHashTable *files;
	GHashTable *old_files;
	volatile int completed_out;
	pthread_t thread_change;
	pthread_t thread_output;
};

int readlink_malloc(const char *p, char **r);
void *change_conf(void *);
void *output(void *);
xmlDocPtr write_config(char *confname, char *keyname, char *value);
xmlDocPtr read_config(char *confname, struct w_config *conf);
