#include "pn53x.h"
#include "typeb.h"
#include "calypso.h"
#include "srix.h"

#define MAX_FRAME_LEN 264

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
    uint8_t blocks[512][32] = { 0 };
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
    
    uint8_t uid[16] = { 0 };
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
            LOG_ERROR("Unknown value '%s'", val.c_str());
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
            LOG_ERROR("Could not open input file '%s'", filename.c_str());
            return;
        }
        int block_id = 0;
        int block_size = -1;
        std::string tok2;
        while (std::getline(fs, tok2) && block_id < dump.max_num_blocks) {
            std::stringstream ss2(tok2);
            size_t cur_byte = 0;

            // TEMP: skip first token for now, which is the block id "[%02X]"
            std::string tok3;
            next_token(ss2, tok3);

            while (get_token_hex_byte(ss2, dump.blocks[block_id][cur_byte]) && (cur_byte < dump.max_block_size)) {
                ++cur_byte;
            }
            if (block_size < 0) {
                block_size = cur_byte;
                dump.block_size = cur_byte;
            } else if (cur_byte != block_size) {
                LOG_ERROR("Block %i has %i bytes instead of %i\n", block_id, cur_byte, block_size);
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
            LOG_ERROR("Unknown command '%s'", cmd.c_str());
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
            LOG_ERROR("Unknown command '%s'", cmd.c_str());
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
                << " - verify\n";
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
                LOG_ERROR("Unknown file identifier '%s'", tok2.c_str());
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
            const uint8_t* rx_data = nullptr;

            int len = calypso_read_records(reader, &rx_data, record_id, false);

            if (len > 0) {
                for (int i = 0; i <= len; ++i) {
                    printf("%02X ", rx_data[i]);
                }
                printf("\n");
            } else {
                printf("Error %d\n", len);
            }

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
        else if (tok.compare("atm_dump_card") == 0) {

            uint16_t files[] = {
                0x0002,
                0x0003,
                0x1000,
                0x1004,
                0x1014,
                0x1015,
                0x2000,
                0x2001,
                0x2004,
                0x2010,
                0x2020,
                0x202a,
                0x202b,
                0x202c,
                0x202d,
                0x2030,
                0x2040,
                0x2050,
                0x2f10,
                0x3100,
                0x3101,
                0x3102,
                0x3104,
                0x3113,
                0x3115,
                0x3f00,
                0x3f04
            };

            // For each of the files stored in the card
            for (int i = 0; i < (sizeof(files) / sizeof(uint16_t)); ++i) {
                // While we can continue to read a sector
                int j = 1;
                printf("SELECTING FILE %04X\n", files[i]);
                if (calypso_select_file(reader, 0, 0, (uint8_t)((files[i] >> 8) & 0xFF), (uint8_t)(files[i] & 0xFF))) {
                    printf("Cannot select file %04X\n", files[i]);
                }

                while (true) {
                    int rxlen;
                    const uint8_t* rx_data = nullptr;
                    rxlen = calypso_read_records(reader, &rx_data, j, false);
                    if (rxlen < 0) {
                        printf("Stop after %d records.\n", j - 1);
                        break;
                    } else {
                        print_hex(rx_data, rxlen);
                    }
                    j++;
                }
            }
        }
        else {
            LOG_ERROR("Unknown command '%s'", cmd.c_str());
        }
    }
    else {
        LOG_ERROR("Unknown mode '%u'", mode);
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
            LOG_ERROR("Could not open input file '%s'", argv[1]);
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
    //shell.execute("srix", true);
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
