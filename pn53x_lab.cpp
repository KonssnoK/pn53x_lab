
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
#define ERROR(...)              { std::cout << "[ERROR] "; printf(__VA_ARGS__); std::cout << std::endl; }



void dump_hex_ascii(const uint8_t *rx, int res, bool dump_address = true) {
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



// ============================================================================

#define MAX_FRAME_LEN 264

// NOTE: these are also defined in libnfc/chips/pn53x-internal.h

#define GetFirmwareVersion      0x02
#define RFConfiguration         0x32
#define InListPassiveTarget     0x4A
#define InCommunicateThru       0x42


class PN53x {

protected:
    nfc_context *m_context = nullptr;
    nfc_device *m_pnd = nullptr;

public:
    ~PN53x() {
        disconnect();
    }

    int connect() {
        if (!m_context) {
            nfc_init(&m_context);
            if (!m_context) {
                ERROR("Could not init libnfc");
                return -1;
            }
        }
        if (!m_pnd) {
            m_pnd = nfc_open(m_context, nullptr);
            if (!m_pnd) {
                ERROR("Could not open reader");
                return -1;
            }
        }
        if (nfc_initiator_init(m_pnd) < 0) {
            ERROR("Error initializing initiator");
            return -1;
        }
        printf("Reader '%s' opened successfully\n", nfc_device_get_name(m_pnd));
        return 0;
    }

    void disconnect() {
        if (m_pnd) {
            nfc_close(m_pnd);
            m_pnd = nullptr;
        }
        if (m_context) {
            nfc_exit(m_context);
            m_context = nullptr;
        }
    }

    int send_command(const uint8_t *tx, int tx_len, const uint8_t **rx2 = NULL, const char *cmd_name = "Rx", bool verbose = true, bool dump_rx_ex = false, bool dump_tx = true) {
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
};

// ============================================================================

// for RFConfiguration
#define CFG_ITEM_RF_FIELD       0x01
#define CFG_ITEM_TIMINGS        0x02
#define CFG_ITEM_MAX_RTY_COM    0x04
#define CFG_ITEM_MAX_RETRIES    0x05


int set_rf_field(PN53x *reader, bool on) {
    if (!on) {
        // field off to deselect card if needed (32 01 00)
        const uint8_t tx[] = {RFConfiguration, CFG_ITEM_RF_FIELD, 0x00};
        reader->send_command(tx, 3, NULL, "RF field off");
    } else {
        const uint8_t tx[] = {RFConfiguration, CFG_ITEM_RF_FIELD, 0x01};
        reader->send_command(tx, 3, NULL, "RF field on");
    }
    return 0;
}


int typeb_setup(PN53x *reader) {
    uint8_t tx[32];
    int tx_len;
    const uint8_t *rx2 = nullptr;

    // 02
    tx[0] = GetFirmwareVersion;
    tx_len = 1;
    if (reader->send_command(tx, tx_len, &rx2, "GetFirmwareVersion", false) < 0)
        return -1;
    printf("IC = 0x%02X, ver = %u.%u, supp = 0x%02X\n", rx2[0], rx2[1], rx2[2], rx2[3]);

    // 32 05 00 00 02

    // set number of tetries of ATR_REQ, PSL_RES to 0, for the
    // InListPassiveTarget to give hand back quickly (after only one REQB)
    tx[0] = RFConfiguration;  // page 101
    tx[1] = CFG_ITEM_MAX_RETRIES;
    tx[2] = 0x00; // MaxRtyATR
    tx[3] = 0x00; // MaxRtyPSL
    tx[4] = 0x00; // MxRtyPassiveActivation
    tx_len = 5;
    if (reader->send_command(tx, tx_len, &rx2, "RFConfiguration retries") < 0)
        return -1;

    // set the timeouts
    // 32 02 00 0B 0E
    tx[0] = RFConfiguration;  // page 101
    tx[1] = CFG_ITEM_TIMINGS;
    tx[2] = 0x00; // RFU
    tx[3] = 0x0B; // ATR_RES timeout, default 0x0B 102.4 ms
    tx[4] = 0x0E; // timeout for InCommunicateThru, default 0x0A 51.2 ms
    // 0x0E = 819.2 ms
    tx_len = 5;
    if (reader->send_command(tx, tx_len, &rx2, "RFConfiguration timings") < 0)
        return -1;

    // 4a 01 03 00

    #define MOD_ISO14443A_106       0x00
    #define MOD_FELICA_212          0x01
    #define MOD_FELICA_424          0x02
    #define MOD_ISO14443B_106       0x03
    #define MOD_JEWEL_106           0x04

    tx[0] = InListPassiveTarget; // page 115
    tx[1] = 1; // MaxTg = max number of targets to be initialized
    tx[2] = MOD_ISO14443B_106;
    tx[3] = 0x00; // AFI
    // tx[4] would be the polling method, absent means timeslot approach
    tx_len = 4;
    if (reader->send_command(tx, tx_len, &rx2, "InListPassiveTarget") < 0)
        return -1;
    printf("Num targets found: %u\n", rx2[0]);

    // NOTE: type B' and SRIX do not respond to this command!
    //   but the InListPassiveTarget is useful to select the modulation and
    //   boud rate to use

    // field off to deselect card if needed (32 01 00)
    set_rf_field(reader, false);

    // field on (32 01 01)
    set_rf_field(reader, true);
    return 0;
}

// ----------------------------------------------------------------------------

int srix_setup(PN53x *reader) {
    // setup reader for type B
    return typeb_setup(reader);
}

int srix_scan(PN53x *reader) {
    uint8_t tx[4];
    const uint8_t *rx2 = nullptr;

    // disable and reenable the rf field, to eventually reset the tag
    set_rf_field(reader, false);
    set_rf_field(reader, true);

    // NOTE: the InCommunicateThru command will use the modulation and boud
    //   rate selected with the InListPassiveTarget command

    tx[0] = InCommunicateThru; // page 136

    // SRIX: initiate (42 06 00)
    tx[1] = 0x06; tx[2] = 0x00;
    if (reader->send_command(tx, 3, &rx2, "SRIX initiate") < 0)
        return -1;

    // select (42 0E chip_id)
    uint8_t chip_id = rx2[1];
    tx[1] = 0x0E; tx[2] = chip_id;
    if (reader->send_command(tx, 3, &rx2, "SRIX select") < 0)
        return -1;

    // get UID
    tx[1] = 0x0B;
    if (reader->send_command(tx, 2, &rx2, "SRIX get UID") < 0)
        return -1;
    return 0;
}

int srix_read_block(PN53x *reader, uint8_t block_id, const uint8_t **rx2) {
    // read block (08 block_id)
    const uint8_t tx[3] = {InCommunicateThru, 0x08, block_id};
    int ret = reader->send_command(tx, 3, rx2, "SRIX read block", false);
    if (ret < 0)
        return ret;
    // expected 5 bytes, unk + block (4 bytes)
    // skip first byte
    if (rx2)
        ++(*rx2);
    return ret - 1;
}

int srix_write_block(PN53x *reader, uint8_t block_id, const uint8_t *data) {
    // write block (09 block_id data (4 bytes))
    const uint8_t tx[] = {InCommunicateThru, 0x09, block_id, data[0], data[1], data[2], data[3]};
    int ret = reader->send_command(tx, sizeof(tx), nullptr, "SRIX write block", false);
    // TODO: do not wait for any response!
    // if (ret < 0)
    //    return ret;
    // read block, to check
    const uint8_t *rx2 = nullptr;
    ret = srix_read_block(reader, block_id, &rx2);
    if (ret < 0) {
        ERROR("Could not read back block %02X", block_id);
        return -1;
    }
    // check
    if (ret != 4 || rx2[0] != data[0] || rx2[1] != data[1] || rx2[2] != data[2] || rx2[3] != data[3]) {
        ERROR("Error writing block %02X (wrote '%2X %2X %2X %2X', read back '%2X %2X %2X %2X')",
              block_id, data[0], data[1], data[2], data[3], rx2[0], rx2[1], rx2[2], rx2[3]);
        return -1;
    }
    return 0;
}

int srix_read_all(PN53x *reader) {
    // scan
    if (srix_scan(reader) < 0)
        return -1;
    // read blocks
    const uint8_t *rx2 = nullptr;
    for (uint8_t block_id = 0; block_id < 128; ++block_id) {
        if (srix_read_block(reader, block_id, &rx2) < 0) {
            printf("Error reading block %2X\n", block_id);
        } else {
            // printf("[%02X] %02X %02X %02X %02X\n", block_id, rx2[0], rx2[1], rx2[2], rx2[3]);
            printf("[%02X] ", block_id);
            dump_hex_ascii(rx2, 4, false);
        }
    }
    // read system area
    if (srix_read_block(reader, 0xFF, &rx2) < 0) {
        printf("Error reading system area\n");
    } else {
        printf("[%02X] %02X %02X %02X %02X\n", 0xFF, rx2[0], rx2[1], rx2[2], rx2[3]);
    }
    return 0;
}

int srix_check_writable(PN53x *reader) {
    const uint8_t *rx2 = nullptr;
    int writable = 0;
    // NOTE: skipping first 5 blocks, as OTP, and next 2 blocks, as binary counters, as
    // writing them means not being able to rewrite them back to the original value!
    for (uint8_t block_id = 7; block_id < 128; ++block_id) {
        // try to read block
        if (srix_read_block(reader, block_id, &rx2) < 0) {
            printf("=> Block %02X not readable\n", block_id);
            continue;
        }
        // save block data
        uint8_t data[4] = {rx2[0], rx2[1], rx2[2], rx2[3]};
        // try to write block
        uint8_t data2[4] = {0x12, 0x34, 0x56, 0x78};
        if (srix_write_block(reader, block_id, data2) < 0) {
            printf("=> Block %02X not writable\n", block_id);
            continue;
        }
        // write back old data
        if (srix_write_block(reader, block_id, data) < 0) {
            printf("=> Error writing the second time to block %02X!!!\n", block_id);
            continue;
        }
        printf("=> Block %02X writable!\n", block_id);
        ++writable;
    }
    printf("%i writable blocks found\n", writable);
    return 0;
}

// ----------------------------------------------------------------------------

int typepreb_setup(PN53x *reader) {
    // setup reader for type B
    return typeb_setup(reader);
}

int typepreb_scan(PN53x *reader, uint8_t *uid, size_t &uid_size) {
    uint8_t tx[10];
    const uint8_t *rx2 = nullptr;

    // passthrough
    tx[0] = InCommunicateThru;

    // type B': ApGen frame (42 01 0b 3f 80)
    tx[1] = 0x01; tx[2] = 0x0B; tx[3] = 0x3F; tx[4] = 0x80;
    if (reader->send_command(tx, 5, &rx2, "ApGen") < 0)
        return -1;
    if (rx2[0] != 0x00)
        ERROR("Error status received");

    // type B': ATTRIB (42 01 0f UID (4 bytes))
    uid[0] = rx2[3]; uid[1] = rx2[4]; uid[2] = rx2[5]; uid[3] = rx2[6];
    uid_size = 4;
    printf("UID: ");
    print_hex(uid, 4);
    tx[1] = 0x01; tx[2] = 0x0F; memcpy(&tx[3], uid, 4);
    if (reader->send_command(tx, 7, &rx2, "ATTRIB") < 0)
        return -1;
    if (rx2[0] != 0x00)
        ERROR("Error status received");
    return 0;
}

int typepreb_disconnect(PN53x *reader) {
    // type B': disconnect (42 01 03)
    const uint8_t tx[] = {InCommunicateThru, 0x01, 0x03};
    return reader->send_command(tx, 3, nullptr, "Disconnect");
}

int typepreb_command(PN53x *reader, const uint8_t *tx, size_t tx_len, const uint8_t **rx2, const char *cmd_name = "Command", bool dump_rx_ex = false) {
    // type B': command
    // 42 01 unk (len+2) 00 ... +[len bytes]
    // unk can be 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E
    // then that nibble is returned back
    static uint8_t unk = 2;
    uint8_t *tx2 = new uint8_t[5 + tx_len];
    unk += 2; if (unk == 0) unk = 2; // TODO: understand what this is
    tx2[0] = InCommunicateThru; tx2[1] = 0x01; tx2[2] = unk & 0x0F; tx2[3] = tx_len + 2; tx2[4] = 0x00;
    memcpy(tx2 + 5, tx, tx_len);
    int ret = reader->send_command(tx2, 5 + tx_len, rx2, cmd_name, true, dump_rx_ex);
    delete tx2;
    if (ret <= 0)
        return ret;
    // parse response
    // 00 01 (4 | unk) len +[len-1 bytes]
    if (rx2 != nullptr) {
        if ((*rx2)[0] != 0x00) {
            ERROR("Unknown status received '%02X'", (*rx2)[0]);
            return -1;
        }
        // make rx2 point to the actual length + returned data
        *rx2 += 3;
    }
    // return the correct length
    return ret - 3;
}


#define VERIFY                      0x20
#define SELECT_FILE                 0xA4
#define READ_BINARY                 0xB0
#define READ_RECORDS                0xB2
#define WRITE_BINARY                0xD0
#define WRITE_RECORD                0xD2


int iso7816_check_response(const uint8_t *rx, size_t rx_len) {
    // check received sw1 and sw2
    uint8_t sw1 = rx[rx_len - 2];
    uint8_t sw2 = rx[rx_len - 1];
    const char *warn = nullptr;
    const char *err = nullptr;
    if (sw1 == 0x62) {
        if (sw2 == 0x81) warn = "Part of returned data may be corrupted";
        else if (sw2 == 0x82) warn = "End of file reached befeore reading Le bytes";
        else if ((sw2 & 0xF0) == 0xC0) warn = "Successful writing, but after using an internal retry routine";  // 'X'!='0' indicates the number of retries: 'X'='0' means that no counter is provided).
    } else if (sw1 == 0x63) {
        if (sw2 == 0x00) warn = "No information given(verification failed)";
        else if ((sw2 & 0xF0) == 0xC0) warn = "Verification failed. CX further retries allowed";
    } else if (sw1 == 0x65) {
        if (sw2 == 0x81) err = "Memory failure (unsuccessful writing)";
    } else if (sw1 == 0x67) {
        if (sw2 == 0x00) err = "Wrong length (wrong Le field)";
    } else if (sw1 == 0x69) {
        if (sw2 == 0x81) err = "Command incompatible with file structure";
        else if (sw2 == 0x82) err = "Security status not satisfied";
        else if (sw2 == 0x83) err = "Authentication method blocked";
        else if (sw2 == 0x84) err = "Referenced data invalidated";
        else if (sw2 == 0x86) err = "Command not allowed (no current EF)";
    } else if (sw1 == 0x6A) {
        if (sw2 == 0x81) err = "Function not supported";
        else if (sw2 == 0x82) err = "File not found";
        else if (sw2 == 0x83) err = "Record not found";
        else if (sw2 == 0x84) err = "Not enough memory space in the file";
        else if (sw2 == 0x85) err = "Lc inconsistent with TLV structure";
        else if (sw2 == 0x86) err = "Incorrect parameters P1-P2";
        else if (sw2 == 0x88) err = "Referenced data not found";
    } else if (sw1 == 0x6B) {
        if (sw2 == 0x00) err = "Wrong parameters (offset outside the EF)";
    } else if (sw1 == 0x6C) {
        err = "Wrong length (Le field indicated in SW2";
    } else if (sw1 == 0x6D) {
        if (sw2 == 0x00) err = "Instruction code not supported or invalid";
        else err = "Instruction code not programmed or invalid (procedure byte), (ISO 7816-3)";
    } else if (sw1 == 0x6E) {
        if (sw2 == 0x00) err = "Class not supported";
    }
    printf("SW1 = %02X, SW2 = %02X%s\n", sw1, sw2, ((sw1 == 0x90 && sw2 == 0x00 ? "" : "   !!!")));
    if (err) {
        printf("ERROR: %s\n", err);
        return -1;
    }
    if (warn) {
        printf("Warning: %s\n", warn);
    }
    return 0;
}


int calypso_setup(PN53x *reader) {
    return typepreb_setup(reader);
}

int calypso_scan(PN53x *reader, uint8_t *uid, size_t &uid_size) {
    return typepreb_scan(reader, uid, uid_size);
}

int calypso_select_file(PN53x *reader, uint8_t id0, uint8_t id1, uint8_t id2, uint8_t id3) {
    const uint8_t tx[] = {
        SELECT_FILE,
        0x08, // select from MF (data field = path without the identifier of the MF)
        0x00, // first record, return FCI, FCP = 0x04, FMD = 0x08
        0x04, // length of data
        id0, id1, id2, id3
    };
    const uint8_t *rx2 = nullptr;
    int res = typepreb_command(reader, tx, tx[3] + 4, &rx2, "SELECT_FILE");
    if (res < 0)
        return -1;
    
    if (iso7816_check_response(rx2, res) < 0)
        return -1;
    return 0;
}

int calypso_read_records(PN53x *reader, uint8_t record_id = 0x01, bool read_all = true) {
    // https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands
    // http://www.ttfn.net/techno/smartcards/iso7816_4.html#ss6_5
    // section 6.5 - READ RECORDS

    // b2 01 04 1d

    // NOTE: unk (passed to typepreb_command) must be different from the one used for
    // selecting the file! why is that? boh

    const uint8_t tx[] = {
        READ_RECORDS,
        record_id, // P1: NOTE: 0x00 indicates current record
        read_all ? (uint8_t) 0x05 : (uint8_t) 0x04, // P2: 0x04 = read record P1, 0x05 = read records from P1 to last, 0x06 = read records from last to P1
        // no Lc
        // no Data
        0x00 // Le: length
    };
    const uint8_t *rx2 = nullptr;
    int res = typepreb_command(reader, tx, tx[3] + 4, &rx2, "READ_RECORDS", true);
    if (res < 0)
        return -1;
    
    if (iso7816_check_response(rx2, res) < 0)
        return -1;
    return 0;
}

int calypso_select_and_read_file(PN53x *reader, uint8_t id0, uint8_t id1, uint8_t id2, uint8_t id3) {
    // select file
    if (calypso_select_file(reader, id0, id1, id2, id3) < 0)
        return -1;
    // read file
    return calypso_read_records(reader);
}

int calypso_read_binary(PN53x *reader) {
    // https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands
    // section 6.1 - READ BINARY

    // b0 00 00 ff
    // if p1 = 00 and p2 = 00 then offset = 0

    const uint8_t tx[] = {
        READ_BINARY,
        0x00,
        0x00,
        0x00 // length
    };
    const uint8_t *rx2 = nullptr;
    int res = typepreb_command(reader, tx, 4, &rx2, "READ_BINARY", true);
    if (res < 0)
        return -1;
    
    if (iso7816_check_response(rx2, res) < 0)
        return -1;
    
    return 0;
}

int calypso_write_record(PN53x *reader, uint8_t record_id, const uint8_t *data, size_t data_size) {
    // https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands
    // section 6.6 - WRITE RECORD

    /*
    Tx: 42  01  0a  06  00  b2  01  04  00  
    THE RECORD:
    00) 00 01 4A 20
                    78 4C 61 1B   |  ..J xLa.
    08) 07 24 00 0D 01 28 F7 3D   |  .$...(.=
    10) 00 00 00 00 00 00 00 00   |  ........
    18) 00 00 00 00 00 00 00 00   |  ........
    20) 00
           90 00                  |  ...
    */

    // 78 4C 61 1B 07 24 00 0D 01 28 F7 3D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    // 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D

    // d2 <record_id> 04 <len> <data>

    uint8_t *tx = new uint8_t[4 + data_size];
    tx[0] = WRITE_RECORD;
    tx[1] = record_id;  // P1: NOTE: 0x00 indicates current record
    tx[2] = 0x04;  // P2: 0x04 = read record P1
    tx[3] = (uint8_t) data_size;  // length
    memcpy(tx + 4, data, data_size);
    const uint8_t *rx2 = nullptr;
    int res = typepreb_command(reader, tx, 4 + data_size, &rx2, "WRITE_RECORD");
    delete tx;
    if (res < 0)
        return -1;
    
    if (iso7816_check_response(rx2, res) < 0)
        return -1;
    return 0;
}

int calypso_verify(PN53x* reader)
{
    const uint8_t tx[] = {
        VERIFY,
        0x00, // P1 alwys 00
        0x80, // P2
        0x00
    };
    const uint8_t* rx2 = nullptr;
    int res = typepreb_command(reader, tx, 4, &rx2, "VERIFY");
    if (res < 0)
        return -1;

    if (iso7816_check_response(rx2, res) < 0)
        return -1;
    return 0;
}

// ============================================================================

size_t read_hex_bytes(std::istream &is, uint8_t *buff, size_t max_len) {
    std::string tok;
    uint32_t temp = 0;
    size_t cur = 0;
    while (std::getline(is, tok, ' ')) {
        if (!tok.size())
            continue;
        /*if (sscanf(tok.c_str(), "%2x", &temp)) {
            buff[cur] = temp & 0xFF;
            ++cur;
        }*/
        char *endptr = nullptr;
        errno = 0;
        uint32_t temp = strtoul(tok.c_str(), &endptr, 16);
        if (errno == 0 && endptr != nullptr) {
            buff[cur] = temp & 0xFF;
            ++cur;
        }
    }
    return cur;
}

bool next_token(std::istream &is, std::string &tok) {
    while (std::getline(is, tok, ' ')) {
        if (!tok.size())
            continue;
        return true;
    }
    return false;
}

bool get_token_hex_byte(std::istream &is, uint8_t &out) {
    // read next token
    std::string tok;
    if (!next_token(is, tok))
        return false;
    // parse token as hex byte
    // if (sscanf(tok.c_str(), "%2x", &out) == 0)
    char *endptr = nullptr;
    errno = 0;
    uint32_t temp = strtoul(tok.c_str(), &endptr, 16);
    if (errno != 0 || endptr == nullptr)
        return false;
    out = temp & 0xFF;
    return true;
}


typedef struct Dump {
    uint8_t blocks[512][32];
    uint8_t block_size = 0;
    int num_blocks = 0;
    size_t max_block_size = 32;
    int max_num_blocks = 512;
} Dump;


typedef enum {
    MODE_ROOT = 0,
    MODE_SRIX = 1,
    MODE_CALYPSO = 2
} EMode;

class ReaderShell {
public:
    PN53x *reader = nullptr;
    EMode mode = MODE_ROOT;
    const char *prompt = "> ";
    bool terminated = false;
    
    uint8_t uid[16];
    size_t uid_size = 0;

    Dump dump;    

    void execute(const std::string &cmd, bool echo_cmd = false);
};

void ReaderShell::execute(const std::string &cmd, bool echo_cmd) {
    // build string stream, for simplifying our life (we don't care about performance)
    auto ss = std::stringstream(cmd);

    // get token and exit if empty line
    std::string tok;
    if (!next_token(ss, tok))
        return;
    
    // print command
    if (echo_cmd)
        printf("%s%s\n", prompt, cmd.c_str());

    if (tok.compare("quit") == 0) {
        terminated = true;
        return;
    }
    else if (tok.compare("rf") == 0) {
        std::string val;
        ss >> val;
        if (val.compare("on") == 0) {
            set_rf_field(reader, true);
        }
        else if (val.compare("off") == 0) {
            set_rf_field(reader, false);
        }
        else {
            ERROR("Unknown value '%s'", val.c_str());
        }
    }
    else if (tok.compare("raw") == 0) {
        uint8_t tx[MAX_FRAME_LEN];
        size_t tx_len = read_hex_bytes(ss, tx, sizeof(tx));
        if (tx_len > 0) {
            printf("Raw tx: ");
            print_hex(tx, tx_len);
            reader->send_command(tx, tx_len, nullptr, "Raw rx", true, true);
        }
    }
    else if (tok.compare("load_dump") == 0) {
        std::string filename;
        if (!next_token(ss, filename)) {
            printf("Usage: load_dump <filename> (without spaces!)\n");
            return;
        }
        // open file
        std::ifstream fs;
        fs.open(filename, std::fstream::in);
        if (!fs) {
            ERROR("Could not open input file '%s'", filename.c_str());
            return;
        }
        int block_id = 0;
        int block_size = -1;
        std::string tok2;
        while (std::getline(fs, tok2) && block_id < dump.max_num_blocks) {
            std::stringstream ss2(tok2);
            int cur_byte = 0;

            // TEMP: skip first token for now, which is the block id "[%02X]"
            std::string tok3;
            next_token(ss2, tok3);

            while (get_token_hex_byte(ss2, dump.blocks[block_id][cur_byte]) && cur_byte < dump.max_block_size) {
                ++cur_byte;
            }
            if (block_size < 0) {
                block_size = cur_byte;
                dump.block_size = cur_byte;
            } else if (cur_byte != block_size) {
                ERROR("Block %i has %i bytes instead of %i\n", block_id, cur_byte, block_size);
                return;
            }
            ++block_id;
        }
        dump.num_blocks = block_id;
        printf("%i blocks of %i bytes read\n", dump.num_blocks, dump.block_size);
        // dump dump
        for (int i = 0; i < dump.num_blocks; ++i) {
            printf("[%02X] ", i);
            dump_hex_ascii(dump.blocks[i], dump.block_size, false);
        }
    }
    else if (mode == MODE_ROOT) {
        if (tok.compare("exit") == 0 || tok.compare("back") == 0) {
            terminated = true;
            return;
        }
        else if (tok.compare("help") == 0) {
            std::cout << "Available commands:\n"
                      << " - quit: exit\n"
                      << " - rf on/off: enable/disable RF field\n"
                      << " - raw <hex bytes>: send raw PN53x command\n"
                      << " - load_dump: <filename>: load a dump\n"
                      << " - modes: list available modes\n"
                      << " - srix: enter SRIX mode\n"
                      << " - calypso: enter Calypso mode\n";
        }
        else if (tok.compare("srix") == 0) {
            mode = MODE_SRIX;
            prompt = "srix> ";
            srix_setup(reader);
        }
        else if (tok.compare("calypso") == 0) {
            mode = MODE_CALYPSO;
            prompt = "calypso> ";
            calypso_setup(reader);
        }
        else if (tok.compare("modes") == 0) {
            printf("Modes: srix, calypso\n");
        }        
        else {
            ERROR("Unknown command '%s'", cmd.c_str());
        }
    }
    else if (mode == MODE_SRIX) {
        if (tok.compare("exit") == 0 || tok.compare("back") == 0) {
            mode = MODE_ROOT;
            prompt = "> ";
        }
        else if (tok.compare("help") == 0) {
            std::cout << "Mode: SRIX\nAvailable commands:\n"
                      << " - exit, back: go back\n"
                      << " - scan: scan for tags\n"
                      << " - read: read a tag\n"
                      << " - read_block <block_id>: read single block\n"
                      << " - write_block <block_id> <data0> <data1> <data2> <data3>: write a block\n"
                      << " - check_writable: check which blocks are writable\n"
                      << " - write_dump: write buffer to tag\n";
        }
        else if (tok.compare("scan") == 0) {
            srix_scan(reader);
        }
        else if (tok.compare("read") == 0) {
            srix_read_all(reader);
        }
        else if (tok.compare("read_block") == 0) {
            uint8_t block_id;
            if (!get_token_hex_byte(ss, block_id)) {
                printf("Usage: read_block <block_id>\n");
                return;
            }
            const uint8_t *rx2 = nullptr;
            int ret = srix_read_block(reader, block_id, &rx2);
            if (ret > 0) {
                dump_hex_ascii(rx2, ret, false);
            }
        }
        else if (tok.compare("write_block") == 0) {
            uint8_t block_id, d[4];
            if (!get_token_hex_byte(ss, block_id) ||
                !get_token_hex_byte(ss, d[0]) ||
                !get_token_hex_byte(ss, d[1]) ||
                !get_token_hex_byte(ss, d[2]) ||
                !get_token_hex_byte(ss, d[3])) {
                printf("Usage: write_block <block_id> <data0> <data1> <data2> <data3>\n");
                return;
            }
            srix_write_block(reader, block_id, d);
        }
        else if (tok.compare("check_writable") == 0) {
            srix_check_writable(reader);
        }
        else if (tok.compare("write_dump") == 0) {
            for (int i = 0; i < dump.num_blocks; ++i) {
                srix_write_block(reader, i, dump.blocks[i]);
            }
        }
        else {
            ERROR("Unknown command '%s'", cmd.c_str());
        }
    }
    else if (mode == MODE_CALYPSO) {
        if (tok.compare("exit") == 0 || tok.compare("back") == 0) {
            mode = MODE_ROOT;
            prompt = "> ";
        }
        else if (tok.compare("help") == 0) {
            std::cout << "Mode: Calypso\nAvailable commands:\n"
                << " - exit, back: go back\n"
                << " - scan: scan for tags\n"
                << " - apdu <hex bytes>: send APDU\n"
                << " - select <filename>: select a file\n"
                << " - select_id <id, 4 hex bytes>: select a file by id\n"
                << " - read_file <filename>: select and read a file\n"
                << " - read_bin: read the current selected file\n"
                << " - read_rec <record_id>: read the specified record of the current selected file\n"
                << " - write_rec <record_i> <hex bytes>: write on the specified record of the current selected file\n"
                << " - verify";
        }
        else if (tok.compare("scan") == 0) {
            calypso_scan(reader, uid, uid_size);
        }
        else if (tok.compare("apdu") == 0) {
            uint8_t tx[MAX_FRAME_LEN];
            size_t tx_len = read_hex_bytes(ss, tx, sizeof(tx));
            if (tx_len > 0) {
                printf("APDU tx: ");
                print_hex(tx, tx_len);
                const uint8_t *rx = nullptr;
                int ret = typepreb_command(reader, tx, tx_len, &rx, "APDU rx");
                if (ret > 0)
                    iso7816_check_response(rx, ret);
            }
        }
        else if (tok.compare("select") == 0 || tok.compare("read_file") == 0) {
            // select/read file
            // read what file
            std::string tok2;
            if (!next_token(ss, tok2)) {
                printf("Usage: %s <filename>\n", tok.c_str());
                printf("Valid filenames: icc, envhol, evlog, conlist, contra, specev, loadlog, purcha\n");
                return;
            }
            uint8_t id0, id1, id2, id3;
            if (tok2.compare("icc") == 0) {
                id0 = 0x3F; id1 = 0x00; id2 = 0x00; id3 = 0x02;
            }
            else if (tok2.compare("envhol") == 0) {
                id0 = 0x20; id1 = 0x00; id2 = 0x20; id3 = 0x01;
            }
            else if (tok2.compare("evlog") == 0) {
                id0 = 0x20; id1 = 0x00; id2 = 0x20; id3 = 0x10;
            }
            else if (tok2.compare("conlist") == 0) {
                id0 = 0x20; id1 = 0x00; id2 = 0x20; id3 = 0x50;
            }
            else if (tok2.compare("contra") == 0) {
                id0 = 0x20; id1 = 0x00; id2 = 0x20; id3 = 0x20;
            }
            else if (tok2.compare("specev") == 0) {
                id0 = 0x20; id1 = 0x00; id2 = 0x20; id3 = 0x40;
            }
            else if (tok2.compare("loadlog") == 0) {
                id0 = 0x10; id1 = 0x00; id2 = 0x10; id3 = 0x14;
            }
            else if (tok2.compare("purcha") == 0) {
                id0 = 0x10; id1 = 0x00; id2 = 0x10; id3 = 0x15;
            }
            else {
                ERROR("Unknown file identifier '%s'", tok2.c_str());
                return;
            }
            // select only or read?
            if (tok.compare("select") == 0) {
                calypso_select_file(reader, id0, id1, id2, id3);
            } else {
                calypso_select_and_read_file(reader, id0, id1, id2, id3);
            }
        }
        else if (tok.compare("select_id") == 0) {
            uint8_t id0, id1, id2, id3;
            if (!get_token_hex_byte(ss, id0) ||
                !get_token_hex_byte(ss, id1) ||
                !get_token_hex_byte(ss, id2) ||
                !get_token_hex_byte(ss, id3)) {
                printf("Usage: select_id <id, 4 hex bytes>\n");
                return;
            }
            calypso_select_file(reader, id0, id1, id2, id3);
        }
        else if (tok.compare("select_force") == 0) {
            // Force selection of available files given a partial ID
            uint8_t id0, id1, id2;
            if (!get_token_hex_byte(ss, id0) ||
                !get_token_hex_byte(ss, id1) ||
                !get_token_hex_byte(ss, id2)) {
                printf("Usage: select_force <3 hex bytes>\n");
                return;
            }
            uint8_t map[256] = { 0 };
            for (int i = 0; i <= 0xFF; ++i) {
                if (!calypso_select_file(reader, id0, id1, id2, i)) {
                    map[i] = 1;
                }
            }
            printf("DISCOVERED MAP\n");
            for (int i = 0; i <= 0xFF; ++i) {
                if (map[i]) {
                    printf("%02X ", i);
                }
            }
            printf("\n");
        }
        else if (tok.compare("read_rec") == 0) {
            uint8_t record_id = 0;
            if (!get_token_hex_byte(ss, record_id)) {
                printf("Usage: read_rec <record_id>\n");
                return;
            }
            calypso_read_records(reader, record_id, false);
        }
        else if (tok.compare("read_bin") == 0) {
            calypso_read_binary(reader);
        }
        else if (tok.compare("write_rec") == 0) {
            uint8_t record_id = 0;
            if (!get_token_hex_byte(ss, record_id)) {
                printf("Usage: write_rec <record_id> <hex bytes>\n");
                return;
            }
            uint8_t tx[MAX_FRAME_LEN];
            size_t tx_len = read_hex_bytes(ss, tx, sizeof(tx));
            if (!tx_len) {
                printf("Usage: write_rec <record_id> <hex bytes>\n");
                return;
            }
            calypso_write_record(reader, record_id, tx, tx_len);
        }
        else if (tok.compare("verify") == 0) {
            calypso_verify(reader);
        }
        else {
            ERROR("Unknown command '%s'", cmd.c_str());
        }
    }
    else {
        ERROR("Unknown mode '%u'", mode);
    }
}

// ============================================================================

int main(int argc, char **argv) {
    // open file if passed from arg
    std::ifstream file_stream;
    if (argc >= 2) {
        // open file
        file_stream.open(argv[1], std::fstream::in);
        if (!file_stream) {
            ERROR("Could not open input file '%s'", argv);
            return EXIT_FAILURE;
        }
    }
    // use file if passed, otherwise stdin
    std::istream &input_stream = file_stream.is_open() ? file_stream : std::cin;

    // connect to reader
    PN53x reader;
    if (reader.connect() != 0)
        return EXIT_FAILURE;

    // shell environment
    ReaderShell shell;
    shell.reader = &reader;

    // init commands
    // shell.execute("calypso", true);
    shell.execute("srix", true);
    shell.execute("scan", true);

    // internal shell loop
    std::string cmd;
    while (!shell.terminated) {
#if defined(HAVE_READLINE)
        if (!file_stream.is_open()) {
            char *cmd2 = readline(shell.prompt);
            if (cmd2 == nullptr)
                break;
            add_history(cmd2);
            // copy
            cmd = cmd2;
            // free temporary string
            free(cmd2);
        } else
#endif //HAVE_READLINE
        {
            std::cout << shell.prompt;
            if (!std::getline(input_stream, cmd))
                break;
        }

        // execute command, echoing it back if from file stream
        shell.execute(cmd, file_stream.is_open());
    }
    return 0;
}
