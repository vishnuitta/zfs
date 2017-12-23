dnl #
dnl # Test that libaio is installed (userspace wrapper for kernel aio syscalls)
dnl #
AC_DEFUN([ZFS_AC_CONFIG_USER_LIBAIO], [
	AC_MSG_CHECKING([Linux native AIO library])
	AC_TRY_COMPILE([
		#include <libaio.h>
		#include <stddef.h>
	],[
		io_setup(0, NULL);
	],[
		AC_MSG_RESULT(yes)
	],[
		AC_MSG_ERROR([Missing linux AIO library. Install libaio-dev package.])
	])
])

