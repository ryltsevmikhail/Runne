#include <sys/stat.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <mach/vm_prot.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/proc_info.h>
#include <unistd.h>

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

/* Match only dyld image zero, the process's actual main executable mapping. */
int runne_macos_fd_is_current_executable_file(int fd) {
    const struct mach_header *header = _dyld_get_image_header(0);
    if (header == NULL) {
        return 0;
    }
    uint64_t address = (uint64_t)(uintptr_t)header;
    struct proc_regionwithpathinfo region = {0};
    int bytes = proc_pidinfo(
        getpid(),
        PROC_PIDREGIONPATHINFO,
        address,
        &region,
        (int)sizeof(region)
    );
    if (bytes != (int)sizeof(region) ||
        region.prp_prinfo.pri_size == 0 ||
        (region.prp_prinfo.pri_protection & VM_PROT_EXECUTE) == 0 ||
        address < region.prp_prinfo.pri_address ||
        address - region.prp_prinfo.pri_address >= region.prp_prinfo.pri_size) {
        return 0;
    }
    struct stat metadata;
    struct vinfo_stat vnode = region.prp_vip.vip_vi.vi_stat;
    if (fstat(fd, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) ||
        metadata.st_nlink != 1 ||
        !S_ISREG(vnode.vst_mode) ||
        vnode.vst_nlink != 1 ||
        (uint64_t)metadata.st_dev != (uint64_t)vnode.vst_dev ||
        (uint64_t)metadata.st_ino != vnode.vst_ino) {
        return 0;
    }
    return 1;
}
