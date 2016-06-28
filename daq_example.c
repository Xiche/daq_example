/*
** Copyright (C) 2016 Michael R. Altizer <xiche@verizon.net>
** All rights reserved.
**
** This software may be modified and distributed under the terms
** of the BSD license.  See the LICENSE file for details.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <daq_api.h>
#include <sfbpf.h>

#define DAQ_EXAMPLE_VERSION 1

typedef struct _example_context
{
    char *device;
    char *filter;
    int snaplen;
    int timeout;
    bool debug;
    struct sfbpf_program fcode;
    volatile bool break_loop;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
} Example_Context_t;

static void destroy_example_daq_context(Example_Context_t *exc)
{
    if (exc)
    {
        free(exc->device);
        free(exc->filter);
        free(exc);
    }
}

static int example_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    Example_Context_t *exc;
    DAQ_Dict *entry;
    int rval;

    exc = calloc(1, sizeof(Example_Context_t));
    if (!exc)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new example context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    exc->device = strdup(config->name);
    if (!exc->device)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    exc->snaplen = config->snaplen;
    exc->timeout = config->timeout;

    for (entry = config->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, "debug"))
            exc->debug = true;
    }

    exc->state = DAQ_STATE_INITIALIZED;

    *ctxt_ptr = exc;
    return DAQ_SUCCESS;

err:
    destroy_example_daq_context(exc);

    return rval;
}

static int example_daq_set_filter(void *handle, const char *filter)
{
    Example_Context_t *exc = (Example_Context_t *) handle;
    struct sfbpf_program fcode;

    if (exc->filter)
        free(exc->filter);

    exc->filter = strdup(filter);
    if (!exc->filter)
    {
        DPE(exc->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(exc->snaplen, DLT_EN10MB, &fcode, exc->filter, 1, 0) < 0)
    {
        DPE(exc->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&exc->fcode);
    exc->fcode.bf_len = fcode.bf_len;
    exc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

static int example_daq_start(void *handle)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    exc->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;
}

static int example_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    return DAQ_SUCCESS;
}

static int example_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    exc->stats.packets_injected++;

    return DAQ_SUCCESS;
}

static int example_daq_breakloop(void *handle)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    exc->break_loop = true;

    return DAQ_SUCCESS;
}

static int example_daq_stop(void *handle)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    exc->state = DAQ_STATE_STOPPED;

    return DAQ_SUCCESS;
}

static void example_daq_shutdown(void *handle)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    destroy_example_daq_context(exc);
}

static DAQ_State example_daq_check_status(void *handle)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    return exc->state;
}

static int example_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    memcpy(stats, &exc->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

static void example_daq_reset_stats(void *handle)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    memset(&exc->stats, 0, sizeof(DAQ_Stats_t));
}

static int example_daq_get_snaplen(void *handle)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    return exc->snaplen;
}

static uint32_t example_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_INJECT | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF;
}

static int example_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *example_daq_get_errbuf(void *handle)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    return exc->errbuf;
}

static void example_daq_set_errbuf(void *handle, const char *string)
{
    Example_Context_t *exc = (Example_Context_t *) handle;

    if (!string)
        return;

    DPE(exc->errbuf, "%s", string);
    return;
}

static int example_daq_get_device_index(void *handle, const char *device)
{
    return DAQ_ERROR_NODEV;
}

DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_EXAMPLE_VERSION,
    .name = "example",
    .type = DAQ_TYPE_INTF_CAPABLE,
    .initialize = example_daq_initialize,
    .set_filter = example_daq_set_filter,
    .start = example_daq_start,
    .acquire = example_daq_acquire,
    .inject = example_daq_inject,
    .breakloop = example_daq_breakloop,
    .stop = example_daq_stop,
    .shutdown = example_daq_shutdown,
    .check_status = example_daq_check_status,
    .get_stats = example_daq_get_stats,
    .reset_stats = example_daq_reset_stats,
    .get_snaplen = example_daq_get_snaplen,
    .get_capabilities = example_daq_get_capabilities,
    .get_datalink_type = example_daq_get_datalink_type,
    .get_errbuf = example_daq_get_errbuf,
    .set_errbuf = example_daq_set_errbuf,
    .get_device_index = example_daq_get_device_index,
    .modify_flow = NULL,
    .hup_prep = NULL,
    .hup_apply = NULL,
    .hup_post = NULL,
};
