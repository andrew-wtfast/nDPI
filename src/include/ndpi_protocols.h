/*
 * ndpi_protocols.h
 *
 * Copyright (C) 2011-22 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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


#ifndef __NDPI_PROTOCOLS_H__
#define __NDPI_PROTOCOLS_H__

#include "ndpi_main.h"


ndpi_port_range* ndpi_build_default_ports_range(ndpi_port_range *ports,
						u_int16_t portA_low, u_int16_t portA_high,
						u_int16_t portB_low, u_int16_t portB_high,
						u_int16_t portC_low, u_int16_t portC_high,
						u_int16_t portD_low, u_int16_t portD_high,
						u_int16_t portE_low, u_int16_t portE_high);

ndpi_port_range* ndpi_build_default_ports(ndpi_port_range *ports,
					  u_int16_t portA,
					  u_int16_t portB,
					  u_int16_t portC,
					  u_int16_t portD,
					  u_int16_t portE);

/* TCP/UDP protocols */
u_int ndpi_search_tcp_or_udp_raw(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow,
				 u_int8_t protocol,
				 u_int32_t saddr, u_int32_t daddr,
				 u_int16_t sport, u_int16_t dport);


void init_diameter_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_afp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_armagetron_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_amqp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_bgp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_bittorrent_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
int ndpi_search_into_bittorrent_cache(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow,
				      u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport);
void init_lisp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_teredo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ciscovpn_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_citrix_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_corba_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_crossfire_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_dcerpc_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_dhcp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_dhcpv6_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_dns_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_dofus_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_dropbox_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_eaq_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_edonkey_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ftp_control_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ftp_data_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_gnutella_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_gtp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_hsrp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_guildwars_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_h323_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_halflife2_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_http_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_iax_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_icecast_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ipp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_irc_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_jabber_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_kakaotalk_voice_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_kerberos_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_kontiki_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ldap_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_lotus_notes_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mail_imap_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mail_pop_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mail_smtp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_maplestory_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_megaco_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mgcp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mining_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mms_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_nats_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mpegts_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mssql_tds_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mysql_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_netbios_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_netflow_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_nfs_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_noe_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_non_tcp_udp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ntp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_openvpn_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_oracle_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_postgres_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ppstream_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_pptp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_qq_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_quake_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_quic_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_radius_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_rdp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_redis_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_rsync_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_rtcp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_rtmp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_rtp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_rtsp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_sflow_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_shoutcast_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_sip_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_imo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_skinny_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_skype_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_smb_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_snmp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_socrates_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_socks_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_spotify_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ssh_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_tls_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_starcraft_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_steam_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_stun_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_syslog_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ssdp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_teamspeak_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_teamviewer_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_telegram_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_telnet_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_tftp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_tvuplayer_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_usenet_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_wsd_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_veohtv_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_vhua_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_viber_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_vmware_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_vnc_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_vxlan_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_warcraft3_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_whois_das_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_world_of_warcraft_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_world_of_kung_fu_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_xbox_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_xdmcp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_zattoo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_zmq_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_stracraft_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ubntac2_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_coap_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mqtt_dissector (struct ndpi_detection_module_struct *ndpi_struct,u_int32_t *id);
void init_someip_dissector (struct ndpi_detection_module_struct *ndpi_struct,u_int32_t *id);
void init_rx_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_git_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_hangout_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_drda_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_bjnp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_smpp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_tinc_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_fix_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_nintendo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_csgo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_checkmk_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_cpha_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_apple_push_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_amazon_video_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_whatsapp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ajp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_memcached_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_nest_log_sink_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ookla_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_modbus_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_capwap_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_zabbix_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_wireguard_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_dnp3_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_104_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_s7comm_dissector(struct ndpi_detection_module_struct *ndpi_struct,u_int32_t *id);
void init_websocket_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_soap_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_dnscrypt_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mongodb_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_among_us_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_hpvirtgrp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_genshin_impact_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_z3950_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_avast_securedns_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_cassandra_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ethernet_ip_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_toca_boca_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_sd_rtn_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_raknet_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_xiaomi_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mpegdash_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_rsh_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ipsec_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_collectd_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_i3d_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_riotgames_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_ultrasurf_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_threema_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_alicloud_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_avast_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_softether_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_activision_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_discord_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_tivoconnect_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_kismet_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_fastcgi_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_natpmp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_syncthing_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_crynet_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_line_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_munin_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_elasticsearch_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_tuya_lp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_tplink_shp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_merakicloud_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_tailscale_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_cod_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_mortal_kombat_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
void init_rocket_league_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id);
/* ndpi_main.c */
extern u_int32_t ndpi_ip_port_hash_funct(u_int32_t ip, u_int16_t port);

#endif /* __NDPI_PROTOCOLS_H__ */
