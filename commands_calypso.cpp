#include "calypso.h"
#include "typeb.h"


int iso7816_check_response(const uint8_t* rx, size_t rx_len)
{
    // check received sw1 and sw2
    uint8_t sw1 = rx[rx_len - 2];
    uint8_t sw2 = rx[rx_len - 1];
    const char* warn = nullptr;
    const char* err = nullptr;
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




#define VERIFY                      0x20
#define SELECT_FILE                 0xA4
#define READ_BINARY                 0xB0
#define READ_RECORDS                0xB2
#define WRITE_BINARY                0xD0
#define WRITE_RECORD                0xD2

int calypso_setup(PN53x* reader)
{
    return typepreb_setup(reader);
}

int calypso_scan(PN53x* reader, uint8_t* uid, size_t& uid_size)
{
    return typepreb_scan(reader, uid, uid_size);
}

int calypso_select_file(PN53x* reader, uint8_t id0, uint8_t id1, uint8_t id2, uint8_t id3)
{
    const uint8_t tx[] = {
        SELECT_FILE,
        0x08, // select from MF (data field = path without the identifier of the MF)
        0x00, // first record, return FCI, FCP = 0x04, FMD = 0x08
        0x04, // length of data
        id0, id1, id2, id3
    };
    const uint8_t* rx2 = nullptr;
    int res = typepreb_command(reader, tx, tx[3] + 4, &rx2, "SELECT_FILE");
    if (res < 0)
        return -1;

    if (iso7816_check_response(rx2, res) < 0)
        return -1;
    return 0;
}

int calypso_read_records(PN53x* reader, const uint8_t** out_data, uint8_t record_id, bool read_all)
{
    // https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands
    // http://www.ttfn.net/techno/smartcards/iso7816_4.html#ss6_5
    // section 6.5 - READ RECORDS

    // b2 01 04 1d

    // NOTE: unk (passed to typepreb_command) must be different from the one used for
    // selecting the file! why is that? boh

    const uint8_t tx[] = {
        READ_RECORDS,
        record_id, // P1: NOTE: 0x00 indicates current record
        read_all ? (uint8_t)0x05 : (uint8_t)0x04, // P2: 0x04 = read record P1, 0x05 = read records from P1 to last, 0x06 = read records from last to P1
        // no Lc
        // no Data
        0x00 // Le: length
    };

    int out_len = typepreb_command(reader, tx, tx[3] + 4, out_data, "READ_RECORDS", false);
    if (out_len < 0)
        return -1;

    if (iso7816_check_response(*out_data, out_len) < 0)
        return -1;
    return out_len;
}


int calypso_select_and_read_file(PN53x* reader, uint8_t id0, uint8_t id1, uint8_t id2, uint8_t id3)
{
    // select file
    if (calypso_select_file(reader, id0, id1, id2, id3) < 0)
        return -1;
    // read file
    const uint8_t* rx_data = nullptr;

    return calypso_read_records(reader, &rx_data);
}

int calypso_read_binary(PN53x* reader)
{
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
    const uint8_t* rx2 = nullptr;
    int res = typepreb_command(reader, tx, 4, &rx2, "READ_BINARY", true);
    if (res < 0)
        return -1;

    if (iso7816_check_response(rx2, res) < 0)
        return -1;

    return 0;
}

int calypso_write_record(PN53x* reader, uint8_t record_id, const uint8_t* data, size_t data_size)
{
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

    uint8_t* tx = new uint8_t[4 + data_size];
    tx[0] = WRITE_RECORD;
    tx[1] = record_id;  // P1: NOTE: 0x00 indicates current record
    tx[2] = 0x04;  // P2: 0x04 = read record P1
    tx[3] = (uint8_t)data_size;  // length
    memcpy(tx + 4, data, data_size);
    const uint8_t* rx2 = nullptr;
    int res = typepreb_command(reader, tx, 4 + data_size, &rx2, "WRITE_RECORD");
    delete[] tx;
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
        0x00, // P2 0x80 specific DF if 1 else global, 0x01X specific reference data
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