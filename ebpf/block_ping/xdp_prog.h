#ifndef XDP_PROG_H
#define XDP_PROG_H

#include <stdint.h>

struct packet_event {
    uint32_t saddr;    // Source IP address
    uint32_t daddr;    // Destination IP address
    uint8_t protocol;  // Protocol type
    uint8_t icmp_type; // ICMP type (if applicable)
};

#endif