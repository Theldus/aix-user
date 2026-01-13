/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

/* Linux to AIX errno table converter. */
#include <stddef.h>
#include "aix_errno.h"
static int e_linux2aix[] = {
	[          EPERM] = AIX_EPERM,
	[         ENOENT] = AIX_ENOENT,
	[          ESRCH] = AIX_ESRCH,
	[          EINTR] = AIX_EINTR,
	[            EIO] = AIX_EIO,
	[          ENXIO] = AIX_ENXIO,
	[          E2BIG] = AIX_E2BIG,
	[        ENOEXEC] = AIX_ENOEXEC,
	[          EBADF] = AIX_EBADF,
	[         ECHILD] = AIX_ECHILD,
	[         EAGAIN] = AIX_EAGAIN,
	[    EWOULDBLOCK] = AIX_EWOULDBLOCK,
	[         ENOMEM] = AIX_ENOMEM,
	[         EACCES] = AIX_EACCES,
	[         EFAULT] = AIX_EFAULT,
	[        ENOTBLK] = AIX_ENOTBLK,
	[          EBUSY] = AIX_EBUSY,
	[         EEXIST] = AIX_EEXIST,
	[          EXDEV] = AIX_EXDEV,
	[         ENODEV] = AIX_ENODEV,
	[        ENOTDIR] = AIX_ENOTDIR,
	[         EISDIR] = AIX_EISDIR,
	[         EINVAL] = AIX_EINVAL,
	[         ENFILE] = AIX_ENFILE,
	[         EMFILE] = AIX_EMFILE,
	[         ENOTTY] = AIX_ENOTTY,
	[        ETXTBSY] = AIX_ETXTBSY,
	[          EFBIG] = AIX_EFBIG,
	[         ENOSPC] = AIX_ENOSPC,
	[         ESPIPE] = AIX_ESPIPE,
	[          EROFS] = AIX_EROFS,
	[         EMLINK] = AIX_EMLINK,
	[          EPIPE] = AIX_EPIPE,
	[           EDOM] = AIX_EDOM,
	[         ERANGE] = AIX_ERANGE,
	[        EDEADLK] = AIX_EDEADLK,
	[      EDEADLOCK] = AIX_EDEADLK, /* There is no 'EDEADLOCK' on AIX, but
	                                    I think EDEADLK is fine. */
	[   ENAMETOOLONG] = AIX_ENAMETOOLONG,
	[         ENOLCK] = AIX_ENOLCK,
	[         ENOSYS] = AIX_ENOSYS,
	[      ENOTEMPTY] = AIX_ENOTEMPTY,
	[          ELOOP] = AIX_ELOOP,
	[         ENOMSG] = AIX_ENOMSG,
	[          EIDRM] = AIX_EIDRM,
	[         ECHRNG] = AIX_ECHRNG,
	[       EL2NSYNC] = AIX_EL2NSYNC,
	[         EL3HLT] = AIX_EL3HLT,
	[         EL3RST] = AIX_EL3RST,
	[         ELNRNG] = AIX_ELNRNG,
	[        EUNATCH] = AIX_EUNATCH,
	[         ENOCSI] = AIX_ENOCSI,
	[         EL2HLT] = AIX_EL2HLT,
	[          EBADE] = AIX_EINVAL,  /* Using EINVAL as there is no EBADE. */
	[          EBADR] = AIX_EINVAL,  /* Using EINVAL as there is no EBADR. */
	[         EXFULL] = AIX_EINVAL,  /* Using EINVAL as there is no EXFULL. */
	[         ENOANO] = AIX_EINVAL,  /* Using EINVAL as there is no ENOANO. */
	[        EBADRQC] = AIX_EINVAL,  /* Using EINVAL as there is no EBADRQC. */
	[        EBADSLT] = AIX_EINVAL,  /* Using EINVAL as there is no EBADSLT. */ 
	[         EBFONT] = AIX_EINVAL,  /* Using EINVAL as there is no EBFONT. */
	[         ENOSTR] = AIX_ENOSTR,  
	[        ENODATA] = AIX_ENODATA,
	[          ETIME] = AIX_ETIME,
	[          ENOSR] = AIX_ENOSR,
	[         ENONET] = AIX_EINVAL, /* Using EINVAL as there is no ENONET. */
	[         ENOPKG] = AIX_EINVAL, /* Using EINVAL as there is no ENOPKG. */
	[        EREMOTE] = AIX_EREMOTE,
	[        ENOLINK] = AIX_ENOLINK,
	[           EADV] = AIX_EINVAL, /* Using EINVAL as there is no EADV. */
	[         ESRMNT] = AIX_EINVAL, /* Using EINVAL as there is no ESMRNT. */
	[          ECOMM] = AIX_EINVAL, /* Using EINVAL as there is no ECOMM. */
	[         EPROTO] = AIX_EPROTO,
	[      EMULTIHOP] = AIX_EMULTIHOP,
	[        EDOTDOT] = AIX_EINVAL, /* Using EINVAL as there is no EDOTDOT. */
	[        EBADMSG] = AIX_EBADMSG,
	[      EOVERFLOW] = AIX_EOVERFLOW,
	[       ENOTUNIQ] = AIX_EINVAL, /* Using EINVAL as there is no ENOTUNIQ. */
	[         EBADFD] = AIX_EINVAL, /* Using EINVAL as there is no EBADFD. */
	[        EREMCHG] = AIX_EINVAL, /* Using EINVAL as there is no EREMCHG. */
	[        ELIBACC] = AIX_EINVAL, /* Using EINVAL as there is no ELIBACC. */
	[        ELIBBAD] = AIX_EINVAL, /* Using EINVAL as there is no ELIBBAD. */
	[        ELIBSCN] = AIX_EINVAL, /* Using EINVAL as there is no ELIBSCN. */
	[        ELIBMAX] = AIX_EINVAL, /* Using EINVAL as there is no ELIBMAX. */
	[       ELIBEXEC] = AIX_EINVAL, /* Using EINVAL as there is no ELIBEXEC. */
	[         EILSEQ] = AIX_EILSEQ,
	[       ERESTART] = AIX_ERESTART,
	[       ESTRPIPE] = AIX_EINVAL, /* Using EINVAL as there is no ESTRPIPE. */
	[         EUSERS] = AIX_EUSERS,
	[       ENOTSOCK] = AIX_ENOTSOCK,
	[   EDESTADDRREQ] = AIX_EDESTADDRREQ,
	[       EMSGSIZE] = AIX_EMSGSIZE,
	[     EPROTOTYPE] = AIX_EPROTOTYPE,
	[    ENOPROTOOPT] = AIX_ENOPROTOOPT,
	[EPROTONOSUPPORT] = AIX_EPROTONOSUPPORT,
	[ESOCKTNOSUPPORT] = AIX_ESOCKTNOSUPPORT,
	[        ENOTSUP] = AIX_ENOTSUP,
	[     EOPNOTSUPP] = AIX_EOPNOTSUPP,
	[   EPFNOSUPPORT] = AIX_EPFNOSUPPORT,
	[   EAFNOSUPPORT] = AIX_EAFNOSUPPORT,
	[     EADDRINUSE] = AIX_EADDRINUSE,
	[  EADDRNOTAVAIL] = AIX_EADDRNOTAVAIL,
	[       ENETDOWN] = AIX_ENETDOWN,
	[    ENETUNREACH] = AIX_ENETUNREACH,
	[      ENETRESET] = AIX_ENETRESET,
	[   ECONNABORTED] = AIX_ECONNABORTED,
	[     ECONNRESET] = AIX_ECONNRESET,
	[        ENOBUFS] = AIX_ENOBUFS,
	[        EISCONN] = AIX_EISCONN,
	[       ENOTCONN] = AIX_ENOTCONN,
	[      ESHUTDOWN] = AIX_ESHUTDOWN,
	[   ETOOMANYREFS] = AIX_ETOOMANYREFS,
	[      ETIMEDOUT] = AIX_ETIMEDOUT,
	[   ECONNREFUSED] = AIX_ECONNREFUSED,
	[      EHOSTDOWN] = AIX_EHOSTDOWN,
	[   EHOSTUNREACH] = AIX_EHOSTUNREACH,
	[       EALREADY] = AIX_EALREADY,
	[    EINPROGRESS] = AIX_EINPROGRESS,
	[         ESTALE] = AIX_ESTALE,
	[        EUCLEAN] = AIX_EINVAL, /* Using EINVAL as there is no EUCLEAN. */
	[        ENOTNAM] = AIX_EINVAL, /* Using EINVAL as there is no ENOTNAM. */
	[        ENAVAIL] = AIX_EINVAL, /* Using EINVAL as there is no ENAVAIL. */
	[         EISNAM] = AIX_EINVAL, /* Using EINVAL as there is no EISNAM. */
	[      EREMOTEIO] = AIX_EINVAL, /* Using EINVAL as there is no EREMOTEIO. */
	[         EDQUOT] = AIX_EDQUOT,
	[      ENOMEDIUM] = AIX_EINVAL, /* Using EINVAL as there is no ENOMEDIUM. */ 
	[    EMEDIUMTYPE] = AIX_EINVAL, /* Using EINVAL as there is no EMEDIUMTYPE. */
	[      ECANCELED] = AIX_ECANCELED,
	[         ENOKEY] = AIX_EINVAL, /* Using EINVAL as there is no ENOKEY. */
	[    EKEYEXPIRED] = AIX_EINVAL, /* Using EINVAL as there is no EKEYEXPIRED. */
	[    EKEYREVOKED] = AIX_EINVAL, /* Using EINVAL as there is no EKEYREVOKED. */
	[   EKEYREJECTED] = AIX_EINVAL, /* Using EINVAL as there is no EKEYREJECTED. */
	[     EOWNERDEAD] = AIX_EOWNERDEAD,
	[ENOTRECOVERABLE] = AIX_ENOTRECOVERABLE,
	[        ERFKILL] = AIX_EINVAL, /* Using EINVAL as there is no ERFKILL. */
	[      EHWPOISON] = AIX_EINVAL, /* Using EINVAL as there is no EHWPOISON. */
};

int errno_linux2aix(int lnx_errno) {
	size_t len = sizeof(e_linux2aix)/sizeof(e_linux2aix[0]);
	if (lnx_errno >= 0 && lnx_errno < len)
		return e_linux2aix[lnx_errno];
	else
		return AIX_EINVAL;
}
