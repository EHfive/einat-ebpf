// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __LOG_H__
#define __LOG_H__

#include <bpf/bpf_helpers.h>

enum bpf_log_level {
    BPF_LOG_LEVEL_NONE = 0,
    BPF_LOG_LEVEL_ERROR,
    BPF_LOG_LEVEL_WARN,
    BPF_LOG_LEVEL_INFO,
    BPF_LOG_LEVEL_DEBUG,
    BPF_LOG_LEVEL_TRACE,
    BPF_LOG_LEVEL_END,
};
#define _BPF_LOG_LEVEL_ERROR_TOKEN "ERROR"
#define _BPF_LOG_LEVEL_WARN_TOKEN "WARN "
#define _BPF_LOG_LEVEL_INFO_TOKEN "INFO "
#define _BPF_LOG_LEVEL_DEBUG_TOKEN "DEBUG"
#define _BPF_LOG_LEVEL_TRACE_TOKEN "TRACE"

// can be overwritten with #undef and re #define on the same name
#define BPF_LOG_LEVEL BPF_LOG_LEVEL_DEBUG;
#define BPF_LOG_TOPIC "default"

#define _bpf_log_logv(level, fmt, args...)                                     \
    ({                                                                         \
        if (BPF_LOG_LEVEL >= level) {                                          \
            bpf_printk("[b-f-c-n][" _##level##_TOKEN "] " BPF_LOG_TOPIC        \
                                                     ": " fmt,                 \
                       ##args);                                                \
        }                                                                      \
    })

#define bpf_log_error(args...) _bpf_log_logv(BPF_LOG_LEVEL_ERROR, args)
#define bpf_log_warn(args...) _bpf_log_logv(BPF_LOG_LEVEL_WARN, args)
#define bpf_log_info(args...) _bpf_log_logv(BPF_LOG_LEVEL_INFO, args)
#define bpf_log_debug(args...) _bpf_log_logv(BPF_LOG_LEVEL_DEBUG, args)
#define bpf_log_trace(args...) _bpf_log_logv(BPF_LOG_LEVEL_TRACE, args)

#endif
