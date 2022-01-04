#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "hsm_log.h"

static bool g_is_log_initialized = false;

static int log_level = LVL_INFO;

void log_init(int level) {
    if (!g_is_log_initialized) {
        if ((LVL_DEBUG <= level) && (level <= LVL_ERROR)) {
            log_level = level;
        }

        g_is_log_initialized = true;

        LOG_INFO("Initialized logging");
    }
}

void log_msg(int level, const char* file, const char* function, int line, const char* fmt_str, ...) {
    static char levels[3][5] = {"DBUG", "INFO", "ERR!"};
    static int syslog_levels[3] = { 7, 6, 3 };

    if (level >= log_level) {
        time_t now;
        char time_buf[sizeof("2018-05-24T00:00:00Z")];
        time(&now);
        strftime(time_buf, sizeof(time_buf), "%FT%TZ", gmtime(&now));
        fprintf(stderr, "<%d>%s [%s] (%s:%s:%d) ", syslog_levels[level], time_buf, levels[level], file, function, line);

        va_list args;
        va_start (args, fmt_str);
        vfprintf(stderr, fmt_str, args);
        va_end (args);

        fprintf(stderr, "\n");
    }
}
