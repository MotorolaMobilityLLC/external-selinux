#include "android_common.h"

int selinux_android_restorecon(const char *file __attribute__((unused)),
                               unsigned int flags __attribute__((unused)))
{
    selinux_log(SELINUX_ERROR, "%s: not implemented for vendor variant of libselinux\n", __FUNCTION__);
    return -1;
}
