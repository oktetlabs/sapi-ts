/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common definitions for checksum package.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@arknetworks.am>
 */
#ifndef __TS_CHECKSUM_LIB_H__
#define __TS_CHECKSUM_LIB_H__

#include "te_errno.h"
#include "asn_usr.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Types of TCP segments used in checksum tests. */
typedef enum sockts_tcp_segment {
    SOCKTS_TCP_SYN,
    SOCKTS_TCP_SYNACK,
    SOCKTS_TCP_FIN,
    SOCKTS_TCP_RST,
} sockts_tcp_segment;

/** List of TCP segments to pass as test argument. */
#define SOCKTS_TCP_SEGMENT_TYPES \
    {"RST", SOCKTS_TCP_RST},      \
    {"FIN", SOCKTS_TCP_FIN},      \
    {"SYN", SOCKTS_TCP_SYN },     \
    {"SYNACK", SOCKTS_TCP_SYNACK}

/** Get TCP segment. */
#define SOCKTS_GET_TCP_SEGMENT_TYPE(_tcp_segment) \
    TEST_GET_ENUM_PARAM(_tcp_segment, SOCKTS_TCP_SEGMENT_TYPES)

/** Types of available checksum values. */
typedef enum sockts_csum_val {
    SOCKTS_CSUM_UNSPEC, /**< Unspecified */
    SOCKTS_CSUM_ZERO,   /**< Zero checksum */
    SOCKTS_CSUM_BAD,    /**< Non-zero invalid checksum */
} sockts_csum_val;

/** List of checksum values to pass as test argument. */
#define SOCKTS_CSUM_VAL_TYPES \
    {"zero", SOCKTS_CSUM_ZERO }, \
    {"bad", SOCKTS_CSUM_BAD}

/** Get checksum value. */
#define SOCKTS_GET_CSUM_VAL(_csum_val) \
    TEST_GET_ENUM_PARAM(_csum_val, SOCKTS_CSUM_VAL_TYPES)

/**
 * Convert TCP header flags value into string represantion.
 *
 * @param flags TCP header flags field value
 *
 * @return null-terminated string with TCP flags definition or "[undefined]"
 *         if the combination is invalid.
 * */
const char *sockts_tcpflags2str(uint8_t flags);

/**
 * Convert TCP segment value of type @ref sockts_tcp_segment to raw TCP flags
 * value.
 *
 * @param segment   The segment type.
 *
 * @return TCP header flags value.
 */
uint8_t sockts_tcpseg2flags(sockts_tcp_segment segment);

/**
 * Convert TCP segment value of type @ref sockts_tcp_segment into string
 * representation.
 *
 * @param segment   The segment type.
 *
 * @return null-terminated string with TCP flags definition.
 */
static inline const char *
sockts_tcpseg2str(sockts_tcp_segment segment)
{
    return sockts_tcpflags2str(sockts_tcpseg2flags(segment));
}

/**
 * Given a traffic TCP template, set its IPv4 header checksum according
 * to @p csum value.
 *
 * @param tmpl  The traffic template
 * @param csum  The checksum value
 *
 * @return Status code
 */
te_errno sockts_set_ip_csum(asn_value *tmpl, sockts_csum_val csum);

/**
 * Given a traffic TCP template, set its TCP header checksum according
 * to @p csum value.
 *
 * @param tmpl  The traffic template
 * @param csum  The checksum value
 *
 * @return Status code
 */
te_errno sockts_set_tcp_csum(asn_value *tmpl, sockts_csum_val csum);

/**
 * Given a traffic UDP template, set its UDP header checksum according
 * to @p csum value.
 *
 * @param tmpl  The traffic template
 * @param csum  The checksum value
 *
 * @return Status code
 */
te_errno sockts_set_udp_csum(asn_value *tmpl, sockts_csum_val csum);

/**
 * Given a traffic TCP template, set checksum field in @p proto header with
 * the @p csum value.
 *
 * @param tmpl  TCP traffic template
 * @param proto Protocol header to corrupt its checksum (supported protocols are
 *              RPC_IPPROTO_IP, RPC_IPPROTO_TCP and RPC_IPPROTO_UDP)
 * @param csum  What value to set as a checksum
 *
 * @return Status code
 */
te_errno sockts_set_hdr_csum(asn_value *tmpl, rpc_socket_proto proto,
                             sockts_csum_val csum);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __TS_CHECKSUM_LIB_H__ */
