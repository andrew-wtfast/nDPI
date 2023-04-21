/*
 * cod.c
 *
 * Copyright (C) 2020 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_COD

#include "ndpi_api.h"

static void ndpi_int_cod_add_connection(struct ndpi_detection_module_struct
                                        *ndpi_struct,
                                        struct ndpi_flow_struct *flow) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_COD,
                               NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_cod(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
    struct ndpi_packet_struct *const packet = &ndpi_struct->packet;

	if (packet->udp == NULL) {
		return;
	}

	u_int16_t dport = ntohs(packet->udp->dest);
	u_int16_t sport = ntohs(packet->udp->source);
	if (sport != 53 && sport != 88 && sport != 500 && sport != 3074 && sport != 3075 && sport != 3544 && sport != 4500 &&
		dport != 53 && dport != 88 && dport != 500 && dport != 3074 && dport != 3075 && dport != 3544 && dport != 4500) {
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	}

	if (packet->payload_packet_len != 29) {
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
		return;
	}

	// TODO
	// xbox seems to be 03 0c on 3075
	// ps3 seems to be 02 0c on 3074
	// officially it's not the case according to activision

	do {
		if ((packet->payload[0] == 0x0c || packet->payload[0] == 0x0d) && 
			packet->payload[1] == 0x02 && packet->payload[2] == 0x00 && 
			(packet->payload[21] == 0x02 || packet->payload[21] == 0x03) && 
			packet->payload[22] == 0x0c) {
			break;
		}
		else {
			NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
			return;
		}
	} while (0);

//	if (!(packet->payload[0] == 0x0c || packet->payload[0] == 0x0d) && 
//		!(packet->payload[1] == 0x02 && packet->payload[2] == 0x00 && packet->payload[21] == 0x03 && packet->payload[22] == 0x0c)) {
//		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
//		return;
//	}

	if (packet->packet_direction == 0 && flow->packet_direction_counter[1] != 0) {
		ndpi_int_cod_add_connection(ndpi_struct, flow);
		return;
	}
	
	if (packet->packet_direction == 1 && flow->packet_direction_counter[0] != 0) {
		ndpi_int_cod_add_connection(ndpi_struct, flow);
		return;
	}

	if (flow->packet_counter > 4) {
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
		return;
	}
}

void init_cod_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                        u_int32_t * id) {
    ndpi_set_bitmask_protocol_detection("Cod", ndpi_struct, *id,
                                        NDPI_PROTOCOL_COD, ndpi_search_cod,
                                        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                        SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                        ADD_TO_DETECTION_BITMASK);
    *id += 1;
}
