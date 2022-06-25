#include "pn53x.h"

// NOTE: these are also defined in libnfc/chips/pn53x-internal.h

#define GetFirmwareVersion      0x02
#define RFConfiguration         0x32
#define InListPassiveTarget     0x4A
#define InCommunicateThru       0x42


// for RFConfiguration
#define CFG_ITEM_RF_FIELD       0x01
#define CFG_ITEM_TIMINGS        0x02
#define CFG_ITEM_MAX_RTY_COM    0x04
#define CFG_ITEM_MAX_RETRIES    0x05


int set_rf_field(PN53x* reader, bool on)
{
    if (!on) {
        // field off to deselect card if needed (32 01 00)
        const uint8_t tx[] = { RFConfiguration, CFG_ITEM_RF_FIELD, 0x00 };
        reader->send_command(tx, 3, NULL, "RF field off");
    } else {
        const uint8_t tx[] = { RFConfiguration, CFG_ITEM_RF_FIELD, 0x01 };
        reader->send_command(tx, 3, NULL, "RF field on");
    }
    return 0;
}

int typeb_setup(PN53x* reader)
{
    uint8_t tx[32];
    int tx_len;
    const uint8_t* rx2 = nullptr;

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

int typepreb_setup(PN53x* reader)
{
    // setup reader for type B
    return typeb_setup(reader);
}

int typepreb_scan(PN53x* reader, uint8_t* uid, size_t& uid_size)
{
    uint8_t tx[10];
    const uint8_t* rx2 = nullptr;

    // passthrough
    tx[0] = InCommunicateThru;

    // type B': ApGen frame (42 01 0b 3f 80)
    tx[1] = 0x01; tx[2] = 0x0B; tx[3] = 0x3F; tx[4] = 0x80;
    if (reader->send_command(tx, 5, &rx2, "ApGen") < 0)
        return -1;
    if (rx2[0] != 0x00)
        LOG_ERROR("Error status received");

    // type B': ATTRIB (42 01 0f UID (4 bytes))
    uid[0] = rx2[3]; uid[1] = rx2[4]; uid[2] = rx2[5]; uid[3] = rx2[6];
    uid_size = 4;
    printf("UID: ");
    print_hex(uid, 4);
    tx[1] = 0x01; tx[2] = 0x0F; memcpy(&tx[3], uid, 4);
    if (reader->send_command(tx, 7, &rx2, "ATTRIB") < 0)
        return -1;
    if (rx2[0] != 0x00)
        LOG_ERROR("Error status received");
    return 0;
}

int typepreb_disconnect(PN53x* reader)
{
    // type B': disconnect (42 01 03)
    const uint8_t tx[] = { InCommunicateThru, 0x01, 0x03 };
    return reader->send_command(tx, 3, nullptr, "Disconnect");
}

int typepreb_command(
    PN53x* reader, 
    const uint8_t* tx, 
    size_t tx_len, 
    const uint8_t** rx2, 
    const char* cmd_name, 
    bool dump_rx_ex)
{
    // type B': command
    // 42 01 unk (len+2) 00 ... +[len bytes]
    // unk can be 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E
    // then that nibble is returned back
    static uint8_t unk = 2;
    uint8_t* tx2 = new uint8_t[5 + tx_len];
    unk += 2; 
    if (unk == 0) 
        unk = 2; // TODO: understand what this is
    tx2[0] = InCommunicateThru; 
    tx2[1] = 0x01; 
    tx2[2] = unk & 0x0F; 
    tx2[3] = tx_len + 2; 
    tx2[4] = 0x00;
    memcpy(tx2 + 5, tx, tx_len);
    int ret = reader->send_command(tx2, 5 + tx_len, rx2, cmd_name, false, dump_rx_ex);
    delete[] tx2;
    if (ret <= 0)
        return ret;
    // parse response
    // 00 01 (4 | unk) len +[len-1 bytes]
    if (rx2 != nullptr) {
        if ((*rx2)[0] != 0x00) {
            LOG_ERROR("Unknown status received '%02X'", (*rx2)[0]);
            return -1;
        }
        // make rx2 point to the actual length + returned data
        *rx2 += 3;
    }
    // return the correct length
    return ret - 3;
}
