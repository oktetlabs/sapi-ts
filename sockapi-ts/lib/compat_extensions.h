/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2025 OKTET Labs Ltd. */

#ifndef __COMPAT_EXTENSIONS_H__
#define __COMPAT_EXTENSIONS_H__

/* Fixme: it is a copy of  talib_sockapi_ts/compat_extensions.h. */

#include "extensions.h"

#ifndef ONLOAD_DELEGATED_SEND_FLAG_IGNORE_ARP
struct onload_delegated_send {
    int nothing;
};

enum onload_delegated_send_rc {
    ONLOAD_DELEGATED_SEND_RC_OK = 0,
    ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET,
    ONLOAD_DELEGATED_SEND_RC_SMALL_HEADER,
    ONLOAD_DELEGATED_SEND_RC_SENDQ_BUSY,
    ONLOAD_DELEGATED_SEND_RC_NOWIN,
    ONLOAD_DELEGATED_SEND_RC_NOARP,
    ONLOAD_DELEGATED_SEND_RC_NOCWIN,
};
#endif /* ONLOAD_DELEGATED_SEND_FLAG_IGNORE_ARP */

#endif /*__COMPAT_EXTENSIONS_H__ */
