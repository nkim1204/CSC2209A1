/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

#ifndef ICMP_ECHO_REPLY
#define ICMP_ECHO_REPLY 0
#endif

#ifndef ICMP_ECHO_REQUEST
#define ICMP_ECHO_REQUEST 8
#endif

struct icmp_hdr{
	uint8_t type;
	uint8_t code;
	uint16_t sum;
	uint32_t unused;
}__attribute__((packed));

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */


} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);


    struct sr_rt* sr_rt = sr->routing_table;
    struct sr_if* sr_if = sr->if_list;

    struct sr_ethernet_hdr *ethHdr = (struct sr_ethernet_hdr *) packet;
    uint16_t ethType = htons(ethHdr->ether_type);

    if(ethType == ETHERTYPE_ARP){
    	struct sr_arphdr * arpHdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

    	if(htons(arpHdr->ar_hrd) != ARPHDR_ETHER){
    		printf("Invalid ARP Hardware Type. Dropping packet.\n");
    		return;
    	}
    	if(htons(arpHdr->ar_pro) != ETHERTYPE_IP){
    		printf("Invalid ARP Protocol Type. Dropping packet.\n");
    		return;
    	}
    	if(htons(arpHdr->ar_op) == ARP_REQUEST){
    		struct sr_if * target_if = destInterfaceCheck(sr, arpHdr->ar_tip);
    		form_arp_reply_packet(ethHdr, arpHdr, target_if);
    		sr_send_packet(sr, packet, len, interface);
    	}
    }
    else if(ethType == ETHERTYPE_IP){
    	struct ip * ip_packet = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    	uint16_t checksum_rcvd = htons(ip_packet->ip_sum);
    	ip_packet->ip_sum = 0;
    	unsigned int ip_hdr_len = ip_packet->ip_v * ip_packet->ip_hl;
    	uint16_t checksum_cptd = compute_checksum((uint16_t*)ip_packet, ip_hdr_len);
    	if(checksum_rcvd != checksum_cptd){
    		printf("IP Header Checksum is incorrect. Dropping packet.\n");
    		return;
    	}
    	struct sr_if* target_if = destInterfaceCheck(sr, (ip_packet->ip_dst).s_addr);
    	if(target_if){
			if(ip_packet->ip_p == IPPROTO_ICMP){
				struct icmp_hdr * icmp = (struct icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + ip_hdr_len);
				if(icmp->type == ICMP_ECHO_REQUEST){
					uint16_t sum_rcvd = htons(icmp->sum);
					icmp->sum = 0;
					uint16_t sum_cptd = compute_checksum((uint16_t *)icmp, ntohs(ip_packet->ip_len) - ip_hdr_len);
					if(sum_rcvd != sum_cptd){
						printf("ICMP Checksum is incorrect. Dropping packet.\n");
						return;
					}
					form_icmp_reply_packet(packet);
					sr_send_packet(sr, packet, len, interface);
				}
			}
    	}
    }

    printf("*** -> Received packet of length %d\n",len);

}/* end sr_ForwardPacket */

void print_packet(uint8_t * packet, int length){
	for(int i = 0; i < length; i++){
		printf("%X ",*(packet+i));
	}
	printf("\n");
}

/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

uint16_t compute_checksum(uint16_t* header, unsigned int length){
	uint32_t sum = 0;


	while(length > 1){
//		printf("ADDING: %X\n",htons(*temp));
		sum = sum + htons(*header);
		header++;
//		printf("AFTER: %X\n",sum);
		length = length - 2;
	}

	if (length > 0){
		sum = sum + *((uint8_t*) header);
	}

	while(sum >> 16){
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
//	printf("CHECMSUM: %X\n",(uint16_t)~sum);
	return (uint16_t)(~sum);
}

struct sr_if * destInterfaceCheck(struct sr_instance *sr, uint32_t target_ip){
	assert(sr);
	struct sr_if * curr_if = sr->if_list;
	assert(curr_if);
	while(curr_if && curr_if->ip != target_ip){
		curr_if = curr_if->next;
	}
	return curr_if;
}

void form_arp_reply_packet(struct sr_ethernet_hdr * ethHdr, struct sr_arphdr * arpHdr, struct sr_if * interface){
	assert(ethHdr); assert(arpHdr); assert(interface);
	memcpy(ethHdr->ether_dhost, ethHdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(ethHdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
	memcpy(arpHdr->ar_tha, arpHdr->ar_sha, ETHER_ADDR_LEN);
	memcpy(arpHdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
	arpHdr->ar_tip = arpHdr->ar_sip;
	arpHdr->ar_sip = interface->ip;
	arpHdr->ar_op = htons(ARP_REPLY);
}

void form_icmp_reply_packet(uint8_t* packet){
	struct sr_ethernet_hdr* ethHdr = (struct sr_ethernet_hdr*)packet;
	struct ip* ip_packet = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));

	unsigned int ip_hdr_len = ip_packet->ip_v * ip_packet->ip_hl;

	struct icmp_hdr * icmp = (struct icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + ip_hdr_len);

	icmp->sum = 0;
	icmp->type = 0;
	icmp->sum = htons(compute_checksum((uint16_t*)icmp, ntohs(ip_packet->ip_len) - ip_hdr_len));

	struct in_addr temp = ip_packet->ip_src;
	ip_packet->ip_src = ip_packet->ip_dst;
	ip_packet->ip_dst = temp;
	ip_packet->ip_sum = 0;
	ip_packet->ip_sum = htons(compute_checksum((uint16_t*)ip_packet, ip_hdr_len));

	uint8_t temp2[ETHER_ADDR_LEN];

	memcpy(temp2, ethHdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(ethHdr->ether_shost, ethHdr->ether_dhost, ETHER_ADDR_LEN);
	memcpy(ethHdr->ether_dhost, temp2, ETHER_ADDR_LEN);
}

