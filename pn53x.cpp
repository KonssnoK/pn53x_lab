#include "pn53x.h"


void dump_hex_ascii(const uint8_t* rx, int res, bool dump_address)
{
    int i = 0;
    const int row_size = 8;
    while (i < res) {
        if (dump_address)
            printf("%02X) ", i);
        for (int j = 0; j < row_size; ++j) {
            if (i + j < res) {
                printf("%02X ", rx[i + j]);
            } else {
                printf("   ");
            }
        }
        printf("  |  ");
        for (int j = 0; j < row_size; ++j) {
            if (i + j < res) {
                if (isprint(rx[i + j])) {
                    printf("%c", rx[i + j]);
                } else {
                    printf(".");
                }
            } else {
                break;
            }
        }
        printf("\n");
        i += row_size;
    }
}

//class PN53x {

    PN53x::~PN53x()
    {
        disconnect();
    }

    int PN53x::connect()
    {
        if (!m_context) {
            nfc_init(&m_context);
            if (!m_context) {
                LOG_ERROR("Could not init libnfc");
                return -1;
            }
        }
        if (!m_pnd) {
            m_pnd = nfc_open(m_context, nullptr);
            if (!m_pnd) {
                LOG_ERROR("Could not open reader");
                return -1;
            }
        }
        if (nfc_initiator_init(m_pnd) < 0) {
            LOG_ERROR("Error initializing initiator");
            return -1;
        }
        printf("Reader '%s' opened successfully\n", nfc_device_get_name(m_pnd));
        return 0;
    }

    void PN53x::disconnect()
    {
        if (m_pnd) {
            nfc_close(m_pnd);
            m_pnd = nullptr;
        }
        if (m_context) {
            nfc_exit(m_context);
            m_context = nullptr;
        }
    }

    int PN53x::send_command(const uint8_t* tx, int tx_len, const uint8_t** rx2, const char* cmd_name, bool verbose, bool dump_rx_ex, bool dump_tx)
    {
        static uint8_t rx[512];
        int res;
        if (verbose && dump_tx) {
            printf("Tx: ");
            print_hex(tx, tx_len);
        }
        // TEMP:
        memset(rx, 0, sizeof(rx));
        if ((res = pn53x_transceive(m_pnd, tx, tx_len, rx, sizeof(rx), 0)) < 0) {
            nfc_perror(m_pnd, cmd_name);
            if (rx2)
                *rx2 = NULL;
            return -1;
        }
        if (res > 0 && verbose) {
            if (!dump_rx_ex) {
                printf("%s: ", cmd_name);
                print_hex(rx, res);
            } else {
                printf("%s:\n", cmd_name);
                dump_hex_ascii(rx, res);
            }
        }
        if (rx2)
            *rx2 = rx;
        return res;
    }
//};

