AC_DEFUN([ZFS_AC_CONFIG_USER_JEMALLOC], [
	JEMALLOCLIB=
	AC_ARG_WITH([jemalloc],
		[AC_HELP_STRING([--with-jemalloc],
		    [use jemalloc memory allocator in libzpool])],
		[AC_CHECK_LIB([jemalloc],
			[mallctl],
			[JEMALLOCLIB="-ljemalloc"],
			[AC_MSG_FAILURE([libjemalloc1 package required])],
			[])],
		[])
	AC_SUBST(JEMALLOCLIB)

])
