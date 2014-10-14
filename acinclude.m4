#
# Author:		Guido Draheim <guidod@gmx.de> 
# Last Modified:	2001-05-03 
# Synopsis:		AC_CHECK_TYPEDEF_(TYPEDEF, HEADER [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]])
# Reference:		http://autoconf-archive.cryp.to/ac_check_typedef.html
#

AC_DEFUN(AC_CHECK_TYPEDEF_,
[dnl
ac_lib_var=`echo $1['_']$2 | sed 'y%./+-%__p_%'`
AC_CACHE_VAL(ac_cv_lib_$ac_lib_var,
[ eval "ac_cv_type_$ac_lib_var='not-found'"
  ac_cv_check_typedef_header=`echo ifelse([$2], , stddef.h, $2)`
  AC_TRY_COMPILE( [#include <$ac_cv_check_typedef_header>],
        [int x = sizeof($1); x = x;],
        eval "ac_cv_type_$ac_lib_var=yes" ,
        eval "ac_cv_type_$ac_lib_var=no" )
  if test `eval echo '$ac_cv_type_'$ac_lib_var` = "no" ; then
     ifelse([$4], , :, $4)
  else
     ifelse([$3], , :, $3)
  fi
])])

dnl AC_CHECK_TYPEDEF(TYPEDEF, HEADER [, ACTION-IF-FOUND,
dnl    [, ACTION-IF-NOT-FOUND ]])
AC_DEFUN(AC_CHECK_TYPEDEF,
[dnl
 AC_MSG_CHECKING([for $1 in $2])
 AC_CHECK_TYPEDEF_($1,$2, [ 
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_[]translit($1, [a-z], [A-Z]))
	],
	AC_MSG_RESULT(no))dnl
])

