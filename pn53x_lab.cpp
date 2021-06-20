
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
    #include <winbase.h>
    #define msleep Sleep
#endif

#include <nfc/nfc.h>
extern "C" {
    #include "utils/nfc-utils.h"
    #include "libnfc/chips/pn53x.h"
}


#define ARRAY_SIZE(a)           (sizeof(a) / sizeof((a)[0]))
#define ERROR(...)              { std::cout << "[ERROR] "; printf(__VA_ARGS__); std::cout << std::endl; }


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

    int send_command(const uint8_t *tx, int tx_len, const uint8_t **rx2 = NULL, const char *cmd_name = "Rx", bool verbose = true, bool dump_rx_ex = false) {
        static uint8_t rx[512];
        int res;
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
                int i = 0;
                const int row_size = 8;
                while (i < res) {
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

int typepreb_command(PN53x *reader, const uint8_t *tx, size_t tx_len, const uint8_t **rx2, const char *cmd_name = "Command", uint8_t unk = 0x0E, bool dump_rx_ex = false) {
    // type B': command
    // 42 01 unk (len+2) 00 ... +[len bytes]
    // unk can be 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E
    // then that nibble is returned back
    uint8_t tx2[5 + tx_len];
    tx2[0] = InCommunicateThru; tx2[1] = 0x01; tx2[2] = unk & 0x0F; tx2[3] = tx_len + 2; tx2[4] = 0x00;
    memcpy(tx2 + 5, tx, tx_len);
    return reader->send_command(tx2, 5 + tx_len, rx2, cmd_name, true, dump_rx_ex);
}

#define SELECT_FILE                 0xA4
#define READ_RECORDS                0xB2

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
        0x00, // first record, return FCI
        0x04, // length of data
        id0, id1, id2, id3
    };
    const uint8_t *rx2 = nullptr;
    int res = typepreb_command(reader, tx, tx[3] + 4, &rx2, "SELECT_FILE", 0x0A);
    if (res < 0)
        return -1;
    // 00  01  (40 | cnt)  (len data + 1) [data]
    // check received status
    if (rx2[0] != 0x00) {
        ERROR("Unknown status received '%02X'", rx2[0]);
        return -1;
    }
    return 0;
}

int calypso_read_records(PN53x *reader, uint8_t record_id = 0x01) {
    // https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands
    // section 6.5

    // b2 01 04 1d

    // NOTE: unk (passed to typepreb_command) must be different from the one used for
    // selecting the file! why is that? boh

    const uint8_t tx[] = {
        READ_RECORDS,
        record_id, // NOTE: 0x00 indicates current record
        0x05, // 0x04 = read record P1, 0x05 = read records from P1 to last, 0x06 = read records from last to P1
        0x00 // length
    };
    const uint8_t *rx2 = nullptr;
    int res = typepreb_command(reader, tx, tx[3] + 4, &rx2, "READ_RECORDS", 0x0C, true);
    if (res < 0)
        return -1;
    // 00  01  (40 | cnt)  (len data + 1) [data]
    // check received status
    if (rx2[0] != 0x00) {
        ERROR("Unknown status received '%02X'", rx2[0]);
        return -1;
    }
    return 0;
}

int calypso_select_and_read_file(PN53x *reader, uint8_t id0, uint8_t id1, uint8_t id2, uint8_t id3) {
    // select file
    if (calypso_select_file(reader, id0, id1, id2, id3) < 0)
        return -1;
    // read file
    return calypso_read_records(reader);
}

// ============================================================================

size_t read_hex_bytes(std::istream &is, uint8_t *buff, size_t max_len) {
    std::string tok;
    size_t cur = 0;
    while (std::getline(is, tok, ' ')) {
        if (!tok.size())
            continue;
        if (sscanf(tok.c_str(), "%2x", &buff[cur]))
            ++cur;
    }
    return cur;
}


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

    void execute(const std::string &cmd, bool echo_cmd = false);
};

void ReaderShell::execute(const std::string &cmd, bool echo_cmd) {
    // build string stream, for simplifying our life (we don't care about performance)
    auto ss = std::stringstream(cmd);

    // check if empty
    if (ss.eof())
        return;

    // check main command
    std::string tok;
    ss >> tok;

    // skip empty command lines
    if (!tok.size())
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
    else if (mode == MODE_ROOT) {
        if (tok.compare("exit") == 0 || tok.compare("back") == 0) {
            terminated = true;
            return;
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
        else if (tok.compare("scan") == 0) {
            srix_scan(reader);
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
        else if (tok.compare("scan") == 0) {
            calypso_scan(reader, uid, uid_size);
        }
        else if (tok.compare("apdu") == 0) {
            uint8_t tx[MAX_FRAME_LEN];
            size_t tx_len = read_hex_bytes(ss, tx, sizeof(tx));
            if (tx_len > 0) {
                printf("APDU tx: ");
                print_hex(tx, tx_len);
                typepreb_command(reader, tx, tx_len, nullptr, "APDU rx");
            }
        }
        else if (tok.compare("select") == 0 || tok.compare("read") == 0) {
            // select/read file
            // read what file
            std::string tok2;
            ss >> tok2;
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
    shell.execute("calypso", true);
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
