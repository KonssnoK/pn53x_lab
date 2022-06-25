#pragma once
#include "pn53x.h"

int iso7816_check_response(const uint8_t* rx, size_t rx_len);

int calypso_setup(PN53x* reader);
int calypso_scan(PN53x* reader, uint8_t* uid, size_t& uid_size);
int calypso_select_file(PN53x* reader, uint8_t id0, uint8_t id1, uint8_t id2, uint8_t id3);
int calypso_read_records(PN53x* reader, const uint8_t** out_data, uint8_t record_id = 0x01, bool read_all = true);
int calypso_select_and_read_file(PN53x* reader, uint8_t id0, uint8_t id1, uint8_t id2, uint8_t id3);
int calypso_read_binary(PN53x* reader);
int calypso_write_record(PN53x* reader, uint8_t record_id, const uint8_t* data, size_t data_size);
int calypso_verify(PN53x* reader);
