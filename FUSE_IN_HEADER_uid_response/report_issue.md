# ntfs_allowed_access() unconditionally bypasses NTFS ACL checks for uid==0

ntfs-3g's `ntfs_allowed_access()` function in `libntfs-3g/security.c` unconditionally grants access when `fuse_in_header.uid == 0`, skipping all NTFS security descriptor (ACL) evaluation. In Linux user namespace environments (rootless Docker, podman, Kubernetes with `userns` remapping), a container's internal `uid=0` is mapped to an unprivileged host UID, but ntfs-3g still grants unrestricted access to all files on the NTFS volume.

This effectively disables NTFS ACL enforcement for any process running as `uid=0` inside a user namespace.

## Steps to Reproduce

1. Mount an NTFS partition with ntfs-3g and `allow_other`:

```bash
ntfs-3g /dev/sdb1 /mnt/ntfs -o allow_other
```

2. The NTFS partition should contain files with restrictive Windows ACLs (e.g., files readable only by a specific Windows user/SID).

3. From a rootless container, attempt to read a restricted file as container `uid=0`:

```bash
# Inside rootless container (uid=0 mapped to host uid=100000)
cat /mnt/ntfs/Users/Administrator/Documents/secret.docx
# Succeeds — should be denied by NTFS ACL
```

4. As a non-zero UID in the container:

```bash
su -s /bin/sh nobody -c "cat /mnt/ntfs/Users/Administrator/Documents/secret.docx"
# Correctly denied
```

## Expected Behavior

Container `uid=0` (mapped to an unprivileged host UID) should be subject to NTFS ACL evaluation and denied access to files where the corresponding NTFS security descriptor does not grant access.

## Actual Behavior

Container `uid=0` bypasses all NTFS ACL checks and is granted full access to every file and directory on the NTFS volume (except execute on non-directory files).

## Affected Code

`libntfs-3g/security.c`, function `ntfs_allowed_access()`, around line 3453:

```c
if (!scx->mapping[MAPUSERS]
    || (!scx->uid
        && (!(accesstype & S_IEXEC)
            || (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY))))
    allow = 1;
```

The `scx->uid` value is derived from `fuse_in_header.uid`. When it equals 0, the function sets `allow = 1` and skips NTFS security descriptor evaluation entirely.

## Suggested Fix

Remove the `uid==0` shortcut and always evaluate the NTFS security descriptor:

```c
if (!scx->mapping[MAPUSERS]) {
    /* No user mapping: require explicit mapping for NTFS ACL evaluation.
       Denying by default is the safest option. */
    allow = 0;
} else {
    /* Always evaluate NTFS security descriptor, even for uid==0.
       This prevents namespace-remapped uid=0 from bypassing ACLs. */
    /* ... existing NTFS ACL evaluation code ... */
}
```

This aligns with native NTFS behavior on Windows where even Administrator accounts are subject to ACL checks (access is granted through explicit ACEs, not a blanket bypass).

---

**Full PoC and scripts**: [GitHub Repository](https://github.com/APEvul-cyber/FUSE_ntfs-3g_vul/tree/main/FUSE_IN_HEADER_uid_response)
