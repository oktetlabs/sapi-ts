/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Epilogue script. 
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 *
 * $Id$
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "epilogue"

#include "sockapi-test.h"
#include "tapi_proc.h"
#include "lib-ts_netns.h"
#include "onload.h"

/**
 * Configurator path to the event which handle onload banners counter
 */
#define CFG_EVENT_ONLOAD_BANNERS_COUNTER    \
    "/agent:"SERIAL_LOG_PARSER_AGENT        \
    "/parser:"SERIAL_LOG_PARSER_NAME        \
    "/event:onload_banners/counter:"

/*
 * ssn_xdp_register may encounter the removal of several zombie stacks,
 * this may take some time.
 */
#define SSN_XDP_UNREG_WAIT_TIMEOUT_MS   60000
#define SSN_XDP_UNREG_RETRY_TIMEOUT_MS  500
#define SSN_XDP_UNREG_RETRIES_NUM       10

/**
 * Stop nfq_daemon on @p pco.
 *
 * @param pco           RPC server
 */
static void
stop_nfqueue(rcf_rpc_server *pco)
{
    tarpc_pid_t     pid;
    int             ret;
    char           *ifname_1 = NULL;
    char           *ifname_2 = NULL;

    if (getenv("SOCKAPI_TS_IP_OPTIONS") == NULL)
        return;

    if (cfg_get_instance_fmt(NULL, (void *)&pid, "/local:%s/nfqueue_pid:",
                             pco->ta) == 0)
    {
        if (pid <= 0)
            return;

        if (rpc_kill(pco, pid, RPC_SIGKILL) < 0)
            ERROR_VERDICT("nfq_daemon with pid: %d died before epilogue", pid);

        ret = cfg_del_instance_fmt(FALSE, "/local:%s/nfqueue_pid:", pco->ta);
        if (ret != 0)
        {
            ERROR_VERDICT("Failed to delete nfq_daemon pid from cfg tree. "
                          "Pid: %d", pid);
        }
    }
    else
    {
        ERROR_VERDICT("Failed to get nfqueue_pid");
    }

    /**
     * Deleting iptables chains related to nfq_daemon that were
     * settled during configure_nfqueue_tst() in prologue.
     * Configurator is unable to roll them back automatically when
     * --ool=ip_options is being used with --ool=bond1, team1 etc.
     */
    ifname_1 = getenv("TE_TST1_IUT");
    if (ifname_1 != NULL)
    {
        CHECK_RC(tapi_cfg_iptables_chain_del(pco->ta, ifname_1, AF_INET,
                                             "mangle", "NFQ_A"));
        ifname_2 = getenv("TE_TST1_IUT_IUT");
    }

    if (!te_str_is_null_or_empty(ifname_2))
    {
        CHECK_RC(tapi_cfg_iptables_chain_del(pco->ta, ifname_2, AF_INET,
                                             "mangle", "NFQ_B"));
    }
}


static void
sockts_check_zombie_stack(rcf_rpc_server *rpcs)
{

    char *out_str = NULL;
    int cnt = 15;
        char       *ef_name;

    ef_name = rpc_getenv(rpcs, "EF_NAME");
    if (ef_name != NULL && strcmp(ef_name, "") != 0)
        CHECK_RC(rcf_rpc_server_create(rpcs->ta, PCO_REUSE_STACK,
                                       NULL));

    rpc_shell_get_all(rpcs, &out_str, "cat /proc/driver/onload/stacks", -1);

    while (strcmp(out_str, "") != 0 && cnt > 0)
    {
        free(out_str);
        out_str = NULL;
        SLEEP(5);
        rpc_shell_get_all(rpcs, &out_str, "cat /proc/driver/onload/stacks",
                          -1);
        cnt--;
    }
    if (cnt == 0)
    {
        sockts_get_zombie_stacks(rpcs);
        SLEEP(1);
        ERROR_VERDICT("Tester run leaves zombie stacks:\n%s", out_str);
    }
}

static void
ssn_xdp_unregister(rcf_rpc_server *rpcs)
{
    unsigned int i;
    rpc_wait_status rc;

    for (i = 0; i < SSN_XDP_UNREG_RETRIES_NUM; i++)
    {
        rpcs->timeout = SSN_XDP_UNREG_WAIT_TIMEOUT_MS;

        RPC_AWAIT_IUT_ERROR(rpcs);
        rc = rpc_system_ex(rpcs, "%s --unregister --zombie", SSN_XDP_REGISTER);
        if (rc.value == 0)
            break;

        if (i < SSN_XDP_UNREG_RETRIES_NUM)
        {
            te_motivated_msleep(SSN_XDP_UNREG_RETRY_TIMEOUT_MS,
                                "wait for the next attempt to ungregistering");
        }
    }

    if (rc.value != 0)
    {
        ERROR("%s() failed to unregister interfaces on %s after %u "
              "attempts", __func__, rpcs->ta, i);
        ERROR_VERDICT("Unable to unregister interfaces");
    }
}

/**
 * Cleanup.
 *
 * @retval EXIT_SUCCESS     success
 * @retval EXIT_FAILURE     failure
 */
int
main(int argc, char **argv)
{
    rcf_rpc_server *pco_iut;
    rcf_rpc_server *pco_tst;

    char            name[SOCKTS_LEAK_FNAME_MAX_LEN];
    char            name_p[SOCKTS_LEAK_FNAME_MAX_LEN];

    char           *check_zombie_stacks =
                        getenv("SF_V5_CHECK_ZOMBIE_STACKS");
    char           *kill_zombie_stacks =
                        getenv("SF_V5_KILL_ZOMBIE_STACKS");
    char *st_debug_kmemleak = getenv("ST_DEBUG_KMEMLEAK");

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    if (tapi_onload_run())
    {
        int onload_banners_counter;
        rc = cfg_get_instance_fmt(NULL, &onload_banners_counter,
                                  CFG_EVENT_ONLOAD_BANNERS_COUNTER);
        if (rc == 0)
        {
            if (onload_banners_counter == 0)
            {
                ERROR_VERDICT("No onload banners were found");
            }
            else
            {
                RING("Onload banners have been registered %d times",
                     onload_banners_counter);
            }
        }
        else
        {
            ERROR_VERDICT("Failed to get value of onload banners counter "
                          "from '%s'", CFG_EVENT_ONLOAD_BANNERS_COUNTER);
        }
    }

    rpc_setenv(pco_iut, "LD_PRELOAD", "", 1);

    /* Restart PCO before the final checks:
     * 1. avoid Onload acceleration of pco_iut;
     * 2. make sure RPC server is in adequate state. */
    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    stop_nfqueue(pco_tst);

    sockts_leak_file_name(pco_iut, "_p", name_p, sizeof(name_p));
    sockts_leak_file_name(pco_iut, "_e", name, sizeof(name_p));

#if 1
    sockts_save_netstat_out(pco_iut, name);
    sockts_cmp_netstat_out(name_p, name);
#endif

    if (sockts_zf_shim_run() == FALSE)
    {
        if (check_zombie_stacks != NULL &&
            strcmp(check_zombie_stacks, "yes") == 0)
            sockts_check_zombie_stack(pco_iut);

        if (kill_zombie_stacks != NULL &&
            strcmp(kill_zombie_stacks, "yes") == 0)
            sockts_kill_check_zombie_stack(pco_iut, TRUE);
    }


    if (branch_ssn())
    {
        rcf_rpc_server *pco_reuse_stack = NULL;
        char *ef_name = rpc_getenv(pco_iut, "EF_NAME");

        TEST_STEP("Unregister IUT interfaces for XDP with "
                  "forced removal of zombie stacks");
        if (!te_str_is_null_or_empty(ef_name))
        {
            rc = rcf_rpc_server_get(pco_iut->ta, PCO_REUSE_STACK,
                                    NULL, RCF_RPC_SERVER_GET_EXISTING,
                                    &pco_reuse_stack);
            if (rc == 0)
            {
                RING("Remove the RCF RPC server started for stack reuse");
                CHECK_RC(rcf_rpc_server_destroy(pco_reuse_stack));
            }
            else if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
            {
                TEST_FAIL("rcf_rpc_server_get() returned unexpected error");
            }
        }
        ssn_xdp_unregister(pco_iut);
    }

    unlink(name_p);
    unlink(name);

    if (st_debug_kmemleak != NULL && strcmp(st_debug_kmemleak, "yes") == 0)
    {
        TEST_STEP("Get status of the Kernel Memory Leak Detector on IUT");

        char *ta = NULL;

        CHECK_NOT_NULL((ta = getenv("TE_IUT_TA_NAME")));
        sockts_kmemleak_get_report(ta);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(libts_cleanup_netns());

    TEST_END;
}
