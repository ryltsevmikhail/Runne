#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>

/* Query the open object; never follow a second caller-supplied pathname. */
int runne_macos_fd_has_no_extended_acl(int fd) {
    filesec_t security = filesec_init();
    if (security == NULL) {
        return 0;
    }
    struct stat metadata;
    int present = -1;
    int admitted = 0;
    if (fstatx_np(fd, &metadata, security) == 0 &&
        filesec_query_property(security, FILESEC_ACL, &present) == 0 &&
        present == 0) {
        admitted = 1;
    }
    filesec_free(security);
    return admitted;
}
