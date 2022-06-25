#pragma once
#include "pn53x.h"

int set_rf_field(PN53x* reader, bool on);
int typeb_setup(PN53x* reader);
int typepreb_setup(PN53x* reader);
int typepreb_scan(PN53x* reader, uint8_t* uid, size_t& uid_size);
int typepreb_disconnect(PN53x* reader);
int typepreb_command(PN53x* reader, 
	const uint8_t* tx, 
	size_t tx_len, 
	const uint8_t** rx2, 
	const char* cmd_name = "Command", 
	bool dump_rx_ex = false);



