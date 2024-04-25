/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-fionbio_thread_unblock_send FIONBIO from thread when send() operation is blocked
 *
 * @objective Try @c FIONBIO from thread when @b send() operation
 *            is blocked in another thread.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_addr      IUT IP address
 * @param tst_addr      TESTER IP address 
 *
 * @par Test sequence:
 * -# Create stream socket @p iut_s on @p pco_iut.
 * -# Create stream socket @p tst_s on @p pco_tst.
 * -# Run RPC server @p pco_iut_thread in thread on @p pco_iut.
 * -# Bind @p iut_s to @p iut_addr.
 * -# Bind @p tst_s to @p tst_addr.
 * -# Connect @p iut_s to tst_s,
 * -# Overfill buffers on @p iut_s
 * -# Call @b send(@p iut_s, ...) on @p pco_iut.
 * -# Make socket @p iut_s non-blocking using @c FIONBIO IOCTL request
 *    from @p pco_iut_thread.
 * -# Check that @b send(@p iut_s, ...) on @p pco_iut is not done.
 * -# Check that @b send(@p iut_s, ...) on @p pco_iut_thread 
 *    fails with @b errno EAGAIN.
 * -# Call @b recv(@p acc_s, @p iut_addr) @p on pco_tst.
 * -# Check that @b send(@p iut_s, ...) on @p pco_iut is unblocked.
 * 
 * @author Konstantin Petrov <Konstantin.Petrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionbio_thread_unblock_send"

#include "sockapi-test.h"
#include "tapi_cfg.h"

#define SEND_BUF_LEN 1
#define RECV_BUF_LEN 1024

int
main(int argc, char **argv)
{
    rcf_rpc_server                  *pco_iut = NULL;
    rcf_rpc_server                  *pco_tst = NULL;
    rcf_rpc_server                  *pco_iut_thread = NULL;
    const struct sockaddr           *iut_addr;
    const struct sockaddr           *tst_addr;
    int                              iut_s = -1;
    int                              tst_s = -1;
    int                              acc_s = -1;
    int                              req_val;
    te_bool                          is_done;
    unsigned char                    tx_buf[SEND_BUF_LEN];
    unsigned char                    rx_buf[RECV_BUF_LEN];
    size_t                           tx_buf_len = SEND_BUF_LEN;
    size_t                           rx_buf_len = RECV_BUF_LEN;
    uint64_t                         sent;
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "IUT_thread",
                                          &pco_iut_thread));
    
    iut_s = rpc_socket(pco_iut,
                       rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM,
                       RPC_IPPROTO_TCP);
    tst_s = rpc_socket(pco_tst,
                       rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM,
                       RPC_IPPROTO_TCP);
    
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, 1);
    rpc_connect(pco_iut, iut_s, tst_addr);
    if ( (acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL)) == -1)
        TEST_FAIL("Unable to accept connection on pco_tst side");

    rpc_overfill_buffers(pco_iut, iut_s, &sent);
            
    pco_iut->op = RCF_RPC_CALL;
    rpc_send(pco_iut, iut_s, tx_buf, tx_buf_len, 0);
    
    req_val = TRUE;
    rpc_ioctl(pco_iut_thread, iut_s, RPC_FIONBIO, &req_val);
    TAPI_WAIT_NETWORK;
    
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &is_done));
    if (!is_done)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut_thread);
        if (rpc_send(pco_iut_thread, iut_s, tx_buf, tx_buf_len, 0) != -1)
            TEST_VERDICT("send() on non-blocking socket succeed");
        
        CHECK_RPC_ERRNO(pco_iut_thread, RPC_EAGAIN,
                        "send() on non-blocking socket failed");
        
        rpc_drain_fd_simple(pco_tst, acc_s, NULL);
        
        TAPI_WAIT_NETWORK;

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &is_done));
        if (is_done)
        {
            pco_iut->op = RCF_RPC_WAIT;
            
            if (rpc_send(pco_iut, iut_s, tx_buf, tx_buf_len, 0) == -1)
                TEST_VERDICT("Blocked send() failed unexpectedly");
        }
        else
        {
            TEST_VERDICT("Blocked send() was not unblocked by "
                         "recv() from peer");
        }
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        pco_iut->op = RCF_RPC_WAIT;
        
        if (rpc_send(pco_iut, iut_s, tx_buf, tx_buf_len, 0) == -1)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                            "send() on blocking socket failed");
        }
        else
            TEST_VERDICT("send() on blocking socket "
                         "succeed instead of failure");
    }

    TEST_SUCCESS;

cleanup:
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    if (pco_iut_thread != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));

    TEST_END;
}

