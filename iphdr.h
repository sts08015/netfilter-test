#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t h_v;
    uint8_t tos;
    uint16_t t_len;
    uint16_t t_id;
    uint16_t f_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    Ip src;
    Ip dst;
    uint32_t sip()
    {
        return ntohl(src);
    }
    uint32_t dip()
    {
        return ntohl(dst);
    }
    uint16_t tlen()
    {
        return ntohs(t_len);
    }
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)


