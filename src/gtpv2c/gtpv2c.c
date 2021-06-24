/*
 * Copyright 2019-present Open Networking Foundation
 * Copyright (c) 2003-2018, Great Software Laboratory Pvt. Ltd.
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <arpa/inet.h>
#include "gtpv2c.h"

void
set_gtpv2c_header(struct gtpv2c_header *gtpv2c_tx, uint8_t type, uint32_t teid,
		uint32_t seq)
{

	gtpv2c_tx->gtp.message_type = type;

	gtpv2c_tx->gtp.version = GTP_VERSION_GTPV2C;
	gtpv2c_tx->gtp.piggyback = 0;
	gtpv2c_tx->gtp.teidFlg = 1;
	gtpv2c_tx->gtp.spare = 0;

	gtpv2c_tx->teid.has_teid.teid = htonl(teid);
	gtpv2c_tx->teid.has_teid.seq = htonl(seq) >> 8;
	gtpv2c_tx->teid.has_teid.spare = 0;

	gtpv2c_tx->gtp.len = htons(8);

	return;
}

void
bswap8_array(uint8_t *src, uint8_t *dest, uint32_t len)
{
	for (uint32_t i=0; i<len; i++)
		dest[i] = ((src[i] & 0x0F)<<4 | (src[i] & 0xF0)>>4);

	return;
}

uint32_t
convert_imsi_to_digits_array(uint8_t *src, uint8_t *dest, uint32_t len)
{
	uint8_t msb_digit = 0;
	uint8_t lsb_digit = 0;
	uint8_t num_of_digits = 0;

	for(uint32_t i = 0; i < len; i++)
	{
		lsb_digit = ((src[i] & 0xF0) >> 4);
		dest[(2*i) + 1] = lsb_digit;

		msb_digit = (src[i] & 0x0F);
		dest[2*i] = msb_digit;

		if (lsb_digit != 0x0F)
			num_of_digits = num_of_digits + 2;
		else
			num_of_digits++;
	}

	return num_of_digits;
}
