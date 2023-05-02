/*
 * world_of_tanks.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WORLD_OF_TANKS

#include "ndpi_api.h"

/*
This signature is based on only 2 good pcaps.

There is a lobby flow and a game play flow. 

Game flow:

First client to server packet: Bytes 4-8 = 01 00 00 05 01, Bytes 12-14 = 00 00 00

Client to server packet payload lengths = 27, 28, 36, 36, 36,...,116

Server to client packet payload lengths = 36, x, x, x,..., y

A challenge is deciding on how many packets of length 36 to depend on client to server.
Range observed to date is 23 to 28.

Another challenge is deciding on how many packets of length x to depend on server to client.
Range observed to date is 5 to 26.

RTP issues:

WoT_NA_Central_filtered.pcap udp flow 5 is getting classified as RTP by nDPI after about 12 packets.
This is wrong according to Wireshark and another DPI engine.
So for now we need to classify before RTP fucks it up.
This relates to the challenge of deciding how many packets to inspect mentioned above.

Lobby flow:

First packet. Len = 22
Byte 4-6 = 01 00 00
Bytes 10-12 = 00 00 00 


*/

static void ndpi_search_world_of_tanks(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {

    struct ndpi_packet_struct *const packet = &ndpi_struct->packet;
	uint8_t total_pkts_to_inspect = 10;

	if (ndpi_current_pkt_from_client_to_server(packet, flow)) {
		
		/*
		The specific bytes checked were determined after analysing only 2 pcaps.
		Remove the checks if further analysis with additional pcaps shows this to be a bad idea.
		*/
		if (flow->packet_direction_counter[packet->packet_direction] == 1 
			&& packet->payload_packet_len == 278
			&& memcmp(packet->payload + 4, "\x01\x00\x00\x05\x01", 5) == 0) {
			return;
		}

		if (flow->packet_direction_counter[packet->packet_direction] == 2 && packet->payload_packet_len == 28) {
			return;
		}

		if (flow->packet_direction_counter[packet->packet_direction] > 2 && packet->payload_packet_len == 36) {
			if (flow->packet_counter >= total_pkts_to_inspect) {
				ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WORLD_OF_TANKS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
			}
			return;
		}

		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

		return;

	} else if (ndpi_current_pkt_from_server_to_client(packet, flow)) {

		if (flow->packet_direction_counter[packet->packet_direction] == 1 && packet->payload_packet_len == 36) {
			return;
		}	

		if (flow->packet_direction_counter[packet->packet_direction] == 2) {
			flow->l4.udp.world_of_tanks_pkt_len = packet->payload_packet_len;
			return;
		}

		if (flow->packet_direction_counter[packet->packet_direction] > 2) {
			if (flow->l4.udp.world_of_tanks_pkt_len == packet->payload_packet_len) {
				if (flow->packet_counter >= total_pkts_to_inspect) {
					ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WORLD_OF_TANKS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
				}
				return;
			}
		}

		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	}
}

void init_world_of_tanks_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t * id) {
    ndpi_set_bitmask_protocol_detection("WorldOfTanks", ndpi_struct, *id,
                                        NDPI_PROTOCOL_WORLD_OF_TANKS,
                                        ndpi_search_world_of_tanks,
                                        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                        SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                        ADD_TO_DETECTION_BITMASK);
    *id += 1;
}
