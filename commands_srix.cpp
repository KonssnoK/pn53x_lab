#include "pn53x.h"
#include "typeb.h"

int srix_setup(PN53x* reader)
{
    // setup reader for type B
    return typeb_setup(reader);
}

int srix_scan(PN53x* reader)
{
    uint8_t tx[4];
    const uint8_t* rx2 = nullptr;

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

int srix_read_block(PN53x* reader, uint8_t block_id, const uint8_t** rx2)
{
    // read block (08 block_id)
    const uint8_t tx[3] = { InCommunicateThru, 0x08, block_id };
    int ret = reader->send_command(tx, 3, rx2, "SRIX read block", false);
    if (ret < 0)
        return ret;
    // expected 5 bytes, unk + block (4 bytes)
    // skip first byte
    if (rx2)
        ++(*rx2);
    return ret - 1;
}

int srix_write_block(PN53x* reader, uint8_t block_id, const uint8_t* data)
{
    // write block (09 block_id data (4 bytes))
    const uint8_t tx[] = { InCommunicateThru, 0x09, block_id, data[0], data[1], data[2], data[3] };
    int ret = reader->send_command(tx, sizeof(tx), nullptr, "SRIX write block", false);
    // TODO: do not wait for any response!
    // if (ret < 0)
    //    return ret;
    // read block, to check
    const uint8_t* rx2 = nullptr;
    ret = srix_read_block(reader, block_id, &rx2);
    if (ret < 0) {
        LOG_ERROR("Could not read back block %02X", block_id);
        return -1;
    }
    // check
    if (ret != 4 || rx2[0] != data[0] || rx2[1] != data[1] || rx2[2] != data[2] || rx2[3] != data[3]) {
        LOG_ERROR("Error writing block %02X (wrote '%2X %2X %2X %2X', read back '%2X %2X %2X %2X')",
            block_id, data[0], data[1], data[2], data[3], rx2[0], rx2[1], rx2[2], rx2[3]);
        return -1;
    }
    return 0;
}

int srix_read_all(PN53x* reader)
{
    // scan
    if (srix_scan(reader) < 0)
        return -1;
    // read blocks
    const uint8_t* rx2 = nullptr;
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

int srix_check_writable(PN53x* reader)
{
    const uint8_t* rx2 = nullptr;
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
        uint8_t data[4] = { rx2[0], rx2[1], rx2[2], rx2[3] };
        // try to write block
        uint8_t data2[4] = { 0x12, 0x34, 0x56, 0x78 };
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
