# ntfs-3g: uid 0 skips NTFS ACL

**Affected:** `libntfs-3g/security.c` `ntfs_allowed_access()`.
**CWE:** CWE-250

`scx->uid == 0` (from `fuse_in_header`) grants access. User-namespace root is still 0. Default `!mapping[MAPUSERS]` also allows everyone.

## Reproduce

See `poc_test.sh`.

**Fix:** map FUSE uid through userns; do not treat 0 as Windows Administrator unless it is host root.