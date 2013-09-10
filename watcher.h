#define MAX_CMD 18

struct watcher get_instance(void);

typedef enum {
	SUCCESS,
	FAILURE
} w_status;

struct w_config {
	char *wd;
};

struct item {
        const char *path;
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

	struct w_conf *conf;
};
