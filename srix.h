#pragma once
#include "pn53x.h"

int srix_setup(PN53x* reader);
int srix_scan(PN53x* reader);
int srix_read_block(PN53x* reader, uint8_t block_id, const uint8_t** rx2);
int srix_write_block(PN53x* reader, uint8_t block_id, const uint8_t* data);
int srix_read_all(PN53x* reader);
int srix_check_writable(PN53x* reader);
