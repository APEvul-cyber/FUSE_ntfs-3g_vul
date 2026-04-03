# ntfs-3g Unconditional Root UID Bypass in NTFS ACL Enforcement Allows Privilege Escalation via User Namespaces

## Summary

ntfs-3g's `ntfs_allowed_access()` function in `libntfs-3g/security.c` unconditionally grants access when the requesting user's UID is 0, skipping all NTFS ACL checks. In Linux user namespace environments (rootless containers, Kubernetes pods with user namespace remapping), the namespace-local `uid=0` is mapped to an unprivileged host user, but ntfs-3g still grants unrestricted file access, effectively bypassing the entire NTFS security descriptor enforcement.

## Details

In `libntfs-3g/security.c`, the function `ntfs_allowed_access()` (around line 3453) contains:

```c
if (!scx->mapping[MAPUSERS]
    || (!scx->uid
        && (!(accesstype & S_IEXEC)
            || (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY))))
    allow = 1;
```

When `scx->uid == 0`, access is granted for all operations except execute on non-directory files. The `scx->uid` value originates from `fuse_in_header.uid` provided by the kernel FUSE client.

In a user namespace context:
- A container's internal `uid=0` is mapped to an unprivileged host UID via `/etc/subuid` (e.g., `uid=0` in container → `uid=100000` on host).
- The kernel FUSE client populates `fuse_in_header.uid` with the namespace-local UID value `0`.
- ntfs-3g receives `uid=0` and skips NTFS ACL evaluation, granting the unprivileged container user full read/write access to all files and directories on the NTFS partition.

Additionally, when no user mapping is configured (`!scx->mapping[MAPUSERS]`), all access is unconditionally allowed regardless of UID, compounding the issue in default configurations.

## PoC

```bash
# Host: mount an NTFS partition via ntfs-3g with allow_other
ntfs-3g /dev/sdb1 /mnt/ntfs -o allow_other

# NTFS partition contains files with Windows ACLs restricting access
# e.g., a file owned by SID S-1-5-21-...-1001 with no access for others
```

Test program:

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void) {
    const char *path = "/mnt/ntfs/ConfidentialReport.docx";
    int fd = open(path, O_RDONLY);
    printf("uid=%d open(%s): fd=%d errno=%s\n",
           getuid(), path, fd, fd >= 0 ? "success" : strerror(errno));
    if (fd >= 0) close(fd);
    return 0;
}
```

Results:

```
uid=500  open: fd=3  errno=success     # mapped NTFS owner — correct
uid=1000 open: fd=-1 errno=Permission denied  # other user — correct
uid=0    open: fd=3  errno=success     # root bypass — VULNERABLE
```

In a user namespace, container `uid=0` (mapped to unprivileged host UID) receives the same unrestricted access.

## Impact

ntfs-3g is the standard userspace NTFS driver on Linux, used for mounting Windows NTFS partitions on dual-boot systems, external drives, and shared storage. It faithfully replicates NTFS security descriptors (ACLs) in its access control logic. The `uid==0` bypass undermines this entire security model:

- **Dual-boot systems:** A user running a rootless container on Linux can access all files on a shared NTFS partition that were restricted by Windows ACLs, including other users' home directories and system files.
- **External storage / forensics:** USB drives or disk images mounted via ntfs-3g in containerized forensics pipelines grant container root unrestricted access to all files.
- **Enterprise file servers:** NTFS volumes exposed via ntfs-3g + FUSE on Linux file servers lose ACL enforcement for any namespace-remapped `uid=0` process.
- **Data recovery environments:** Containers accessing NTFS volumes for recovery inherit full access, defeating the principle of least privilege.

## Suggested Fix

Check the specific NTFS security descriptor for the calling user rather than short-circuiting on `uid==0`:

```c
/* Remove or gate the uid==0 bypass in ntfs_allowed_access() */
if (!scx->mapping[MAPUSERS]) {
    /* No user mapping configured — consider denying by default
       or requiring explicit mapping for access */
    allow = 0;  // deny by default without mapping
} else if (!scx->uid) {
    /* uid==0: verify this is genuine host root, not namespace-remapped.
       Conservative fix: always apply ACL checks regardless of uid */
    /* Fall through to normal NTFS ACL evaluation below */
} else {
    /* Normal user: evaluate NTFS security descriptor */
}
```

The most conservative approach is to remove the `uid==0` shortcut entirely and always evaluate the NTFS security descriptor, as native Windows NTFS does not have an analogous "skip ACL for Administrator" bypass at the filesystem level.

---

**Full PoC and scripts**: [GitHub Repository](https://github.com/APEvul-cyber/FUSE_ntfs-3g_vul/tree/main/FUSE_IN_HEADER_uid_response)
