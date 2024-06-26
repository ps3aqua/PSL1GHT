#include <stdio.h>
#include <fcntl.h>
#include <_ansi.h>
#include <_syslist.h>
#include <sys/reent.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/lv2errno.h>

#include <sys/file.h>

int __librt_unlink_r(struct _reent *r, const char *path)
{
	return lv2errno_r(r,sysLv2FsUnlink(path));
}
