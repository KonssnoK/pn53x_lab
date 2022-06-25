#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <functional>
#if defined(HAVE_READLINE)
#include <readline/readline.h>
#include <readline/history.h>
#endif //HAVE_READLINE

#ifndef _WIN32
#include <time.h>
#define msleep(x) \
        do { \
            struct timespec xsleep; \
            xsleep.tv_sec = x / 1000; \
            xsleep.tv_nsec = (x - xsleep.tv_sec * 1000) * 1000 * 1000; \
            nanosleep(&xsleep, NULL); \
        } while (0)
#else
#include <windows.h>
#define msleep Sleep
#endif

#include <nfc/nfc.h>
extern "C" {
#include "utils/nfc-utils.h"
#include "libnfc/chips/pn53x.h"
}

#define ARRAY_SIZE(a)           (sizeof(a) / sizeof((a)[0]))
#define LOG_ERROR(...)          { std::cout << "[ERROR] "; printf(__VA_ARGS__); std::cout << std::endl; }


void dump_hex_ascii(const uint8_t* rx, int res, bool dump_address = true);

class PN53x {

protected:
    nfc_context* m_context = nullptr;
    nfc_device* m_pnd = nullptr;

public:
    ~PN53x();
    int connect();
    void disconnect();

    int send_command(
        const uint8_t* tx,
        int tx_len,
        const uint8_t** rx2 = NULL,
        const char* cmd_name = "Rx",
        bool verbose = true,
        bool dump_rx_ex = false,
        bool dump_tx = true);
};

