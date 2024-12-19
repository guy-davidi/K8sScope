#ifndef XDP_MONITOR_H
#define XDP_MONITOR_H

#include <linux/types.h>

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
};

#endif // XDP_MONITOR_H
