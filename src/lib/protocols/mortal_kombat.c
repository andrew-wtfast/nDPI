/*
 * mortal_kombat.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MORTAL_KOMBAT

#include "ndpi_api.h"

static void ndpi_search_mortal_kombat(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {

	/*
	In addition to the signature implemented below, after the initial two packets
	are exchanged (one from client, once from server) every subsequent packet 
	payload begins with 0xF9000000.
	*/

    struct ndpi_packet_struct *const packet = &ndpi_struct->packet;

	if (flow->packet_direction_counter[packet->packet_direction] == 1) {

		if (packet->packet_direction == 1) {
			if (packet->payload_packet_len >= 17 && (memcmp(packet->payload, "\xFD\x00\x00\x00\x02", 5) == 0)) {
				// Save 16 bytes in order to compare them to the payload in the response
				memcpy(flow->l4.udp.mortal_kombat_bytes, packet->payload + 1, 16);
				return; // continue inspecting
			} else {
				printf("not mortal kombat 1\n");
				NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
				return;
			}
		} else {
			// Compare a portion of this response payload to the payload of the first client to server packet.
			if (packet->payload_packet_len == 21 && (memcmp(flow->l4.udp.mortal_kombat_bytes, packet->payload + 1, 16) == 0)) {
				ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MORTAL_KOMBAT, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
			}
		}
	}

	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_mortal_kombat_dissector(struct ndpi_detection_module_struct
                                  *ndpi_struct, u_int32_t * id) {
    printf("mortal kombat init\n");
    ndpi_set_bitmask_protocol_detection("MortalKombat", ndpi_struct, *id,
                                        NDPI_PROTOCOL_MORTAL_KOMBAT,
                                        ndpi_search_mortal_kombat,
                                        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                        SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                        ADD_TO_DETECTION_BITMASK);
    *id += 1;
}
