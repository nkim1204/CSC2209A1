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
#include "time.h"

#ifdef _WIN32
#ifndef TTL
#define TTL 128
#endif
#elif _WIN64
#ifndef TTL
#define TTL 128
#endif
#elif __APPLE__
#ifndef TTL
#define TTL 64
#endif
#elif __linux
#ifndef TTL
#define TTL 64
#endif
#endif

#ifndef TCP
#define TCP 6
#endif

#ifndef UDP
#define UDP 17
#endif

#ifndef ICMP_ECHO_REPLY
#define ICMP_ECHO_REPLY 0
#endif

#ifndef ICMP_ECHO_REPLY
#define ICMP_ECHO_REPLY 0
#endif

#ifndef ICMP_ECHO_REQUEST
#define ICMP_ECHO_REQUEST 8
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif

#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif

#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif

#ifndef ICMP_HDR_LEN
#define ICMP_HDR_LEN 8
#endif

#ifndef ICMP_DATA_LEN
#define ICMP_DATA_LEN 8
#endif

struct icmp_hdr{
	uint8_t type;
	uint8_t code;
	uint16_t sum;
	uint32_t unused;
}__attribute__((packed));

struct packet{
	uint8_t* packet;
	struct packet* next;
	uint16_t size;
};

struct packet_queue{
	struct packet* first;
	struct packet* last;
};

struct arp_request{
	struct arp_request* prev;
	struct arp_request* next;
	uint32_t ip;
	struct packet_queue* packetQueue;
	struct sr_if* interface;
	uint8_t num;
//	time_t
};

struct arp_request_queue{
	struct arp_request* first;
	struct arp_request* last;
};

struct arp_cache{
	uint32_t ip;
	unsigned char addr[ETHER_ADDR_LEN];
	struct arp_cache* prev;
	struct arp_cache* next;
};

struct arp_cache_queue{
	struct arp_cache* first;
	struct arp_cache* last;
};


static struct arp_request_queue* arpRQ;
static struct arp_cache_queue* arpCQ;

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
    arpRQ = malloc(sizeof(struct arp_request_queue));
    arpRQ->first = 0;
    arpRQ->last = 0;

    arpCQ = malloc(sizeof(struct arp_cache_queue));
    arpCQ->first = 0;
    arpCQ->last = 0;

} /* -- sr_init -- */

uint16_t compute_checksum(uint16_t* header, unsigned int length){
	uint32_t sum = 0;


	while(length > 1){
		sum = sum + htons(*header);
		header++;
		length = length - 2;
	}

	if (length > 0){
		sum = sum + *((uint8_t*) header);
	}

	while(sum >> 16){
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return (uint16_t)(~sum);
}

struct packet* addPacket(struct packet_queue* pq, uint8_t* packet, uint16_t size){
	struct packet* tbaPacket = malloc(sizeof(struct packet));
	tbaPacket->next = 0;
	tbaPacket->packet = (struct uint8_t*)malloc(size);
	memcpy(tbaPacket->packet, packet, size);
	tbaPacket->size = size;
	if(pq->first){
		pq->last->next = tbaPacket;
	}

	else{
		pq->first = tbaPacket;
		pq->last = tbaPacket;
	}

	return tbaPacket;
}

struct arp_request* checkArpRequestQueue(uint32_t ip){
	struct arp_request* curr = arpRQ->first;
	while(curr){
		if(curr->ip == ip){
			return curr;
		}
		curr = curr->next;
	}
	return 0;
}

struct arp_request* addArpRequest(uint8_t* packet, uint16_t size, uint32_t ip, struct sr_if* interface){
	struct arp_request* curr = checkArpRequestQueue(ip);
	if(curr){
		struct packet_queue* pq = curr->packetQueue;
		addPacket(pq, packet, size);
		curr->num += 1;
	}
	else{
		curr = malloc(sizeof(struct arp_request));
		curr->interface = interface;
		curr->ip = ip;
		curr->next = 0;
		curr->packetQueue = (struct packet_queue*)malloc(sizeof(struct packet_queue));
		curr->packetQueue->first = curr->packetQueue->last = 0;
		addPacket(curr->packetQueue, packet, size);
		curr->num = 1;
		if(arpRQ->first){
			arpRQ->last->next = curr;
			curr->prev = arpRQ->last;
			curr->next = 0;
		}
		else{
			arpRQ->first = curr;
			curr->prev = curr->next = 0;
		}
		arpRQ->last = curr;
	}
	printf("COUNT IS: %d\n",curr->num);
	return curr;
}

void sendArpWaitPackets(struct sr_instance* sr, struct arp_request* arpRequest, unsigned char* dAddr){
	struct packet_queue* pq = arpRequest->packetQueue;
	struct packet* p = pq->first;

	while(p){
		uint8_t* packet = p->packet;
		struct ip* ip = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
		ip->ip_ttl -= 1;
		ip->ip_sum = 0;
		ip->ip_sum = htons(compute_checksum((uint16_t*)ip, ip->ip_v * ip->ip_hl));
		memcpy(((struct sr_ethernet_hdr*)(packet))->ether_dhost, dAddr, ETHER_ADDR_LEN);
		memcpy(((struct sr_ethernet_hdr*)(packet))->ether_shost, arpRequest->interface->addr, ETHER_ADDR_LEN);

		sr_send_packet(sr, packet, p->size, arpRequest->interface->name);
//		print_packet(packet,p->size);
		struct packet* temp = p;
		p = p->next;
		free(temp);
		temp = 0;
	}

	if(arpRequest->prev)
		arpRequest->prev->next = arpRequest->next;
	else
		arpRQ->first = arpRequest->next;
	if(arpRequest->next)
		arpRequest->next->prev = arpRequest->prev;
	else
		arpRQ->last = arpRequest->prev;

	free(arpRequest);
	arpRequest = 0;
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

void form_arp_request_packet(struct sr_ethernet_hdr * ethHdr, struct sr_arphdr * arpHdr, struct sr_if * interface, uint32_t dst_ip){
	assert(ethHdr); assert(arpHdr); assert(interface);
	for(int i = 0; i < ETHER_ADDR_LEN; i++){
		ethHdr->ether_dhost[i] = 0xFF;
		arpHdr->ar_tha[i] = 0;
	}

	memcpy(ethHdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
	ethHdr->ether_type = htons(ETHERTYPE_ARP);

	memcpy(arpHdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
	arpHdr->ar_tip = dst_ip;
	arpHdr->ar_sip = interface->ip;
	arpHdr->ar_op = htons(ARP_REQUEST);
	arpHdr->ar_hrd = htons(1);
	arpHdr->ar_pro = htons(ETHERTYPE_IP);
	arpHdr->ar_hln = 6;
	arpHdr->ar_pln = 4;
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

struct sr_rt * search_rt(struct sr_instance * sr, uint8_t *ip){
	assert(ip);
	struct sr_rt * curr_rt = sr->routing_table;
	struct sr_rt * default_rt = 0, * best_rt = 0;
	uint8_t *ip_byte, *rt_byte, *mask_byte;
	uint8_t result, count = 0, best = 0;
	while(curr_rt){
		if(!default_rt){
			if((curr_rt->dest).s_addr == 0){
				default_rt = curr_rt;
			}
		}
		ip_byte = ip;
		rt_byte = (uint8_t*)&((curr_rt->dest).s_addr);
		mask_byte = (uint8_t*)&((curr_rt->mask).s_addr);

		for(int i = 0; i < 4; i++){
//			printf("MASK: %d\tDEST: %d\tIP: %d\n",*(mask_byte+i),*(rt_byte+i),*(ip+i));
			result = (*(mask_byte+i)) & (*(rt_byte+i));
			if(!result){
				break;
			}
			if(result != *(ip_byte+i)){
				break;
			}
			count++;
		}
		if(count > best){
			best = count;
			best_rt = curr_rt;
		}
		count = 0;
		curr_rt = curr_rt->next;
	}
	if(best_rt)
		return best_rt;
	return default_rt;
}


unsigned int init_icmp_err(uint8_t **packet, struct ip* rcvd_ip, unsigned int rcvd_ip_hdr_len, struct sr_ethernet_hdr** ether, struct ip** ip, struct icmp_hdr** icmp){
	unsigned int size = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + ICMP_HDR_LEN + rcvd_ip_hdr_len + ICMP_DATA_LEN;
	if(*packet = (uint8_t*)malloc(size)){
		*ether = (struct sr_ethernet_hdr*)(*packet);
		*ip = (struct ip*)(*packet + sizeof(struct sr_ethernet_hdr));
		*icmp = (struct icmp_hdr*)(*packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
		return size;
	}
	return 0;
}

void init_icmp_ethernet_hdr(struct sr_ethernet_hdr* ether_hdr, unsigned char* src_addr, unsigned char* dst_addr){
	memcpy(ether_hdr->ether_dhost, dst_addr, ETHER_ADDR_LEN);
	memcpy(ether_hdr->ether_shost, src_addr, ETHER_ADDR_LEN);
	ether_hdr->ether_type = htons(ETHERTYPE_IP);
}

void init_icmp_ip_hdr(struct ip* ip_hdr, unsigned int rcvd_ip_hdr_len, uint32_t src_ip, uint32_t dst_ip){
	ip_hdr->ip_v = 4;
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = TTL;
	ip_hdr->ip_p = IPPROTO_ICMP;
	unsigned int hdr_len = ip_hdr->ip_v * ip_hdr->ip_hl;
	ip_hdr->ip_len = htons(hdr_len + ICMP_HDR_LEN + rcvd_ip_hdr_len + ICMP_DATA_LEN);
	(ip_hdr->ip_src).s_addr = src_ip;
	(ip_hdr->ip_dst).s_addr = dst_ip;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = htons(compute_checksum((uint16_t*)ip_hdr,hdr_len));
}

void init_icmp_icmp_hdr_data(struct icmp_hdr* icmp_hdr, uint8_t type, uint8_t code, uint8_t* data, unsigned int data_length){
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->unused = 0;
	icmp_hdr->sum = 0;
	memcpy(icmp_hdr + 1, data, data_length);
	icmp_hdr->sum = htons(compute_checksum((uint16_t*)icmp_hdr, ICMP_HDR_LEN + data_length));
}

struct arp_cache* checkArpCacheQueue(uint32_t ip){
	struct arp_cache* curr = arpCQ->first;
	while(curr){
		if(curr->ip == ip)
			return curr;
		curr = curr->next;
	}
	return 0;
}

struct arp_cache* addArpCache(unsigned char* addr, uint32_t ip){
	struct arp_cache* curr = checkArpCacheQueue(ip);
	if(!curr){
		curr = malloc(sizeof(struct arp_cache));
		memcpy(curr->addr, addr, ETHER_ADDR_LEN);
		curr->ip = ip;
		curr->next = 0;
		if(arpCQ->first){
			arpCQ->last->next = curr;
			curr->prev = arpCQ->last;
			curr->next = 0;
		}
		else{
			arpCQ->first = curr;
			curr->prev = curr->next = 0;
		}
		arpCQ->last = curr;
	}
	else{
		curr->ip = ip;
		memcpy(curr->addr, addr, ETHER_ADDR_LEN);
	}
	return curr;
}

void handle_arp_reply_packet(struct sr_instanc* sr, struct sr_ethernet_hdr* ethHdr, struct sr_arphdr* arpHdr){
	unsigned char* target_addr = arpHdr->ar_sha;
	uint32_t target_ip = arpHdr->ar_sip;
	struct arp_request* arpReq;

	struct arp_cache* arpCache;

	if(!(arpCache = checkArpCacheQueue(target_ip))){
		addArpCache(target_addr,target_ip);
	}

	if(arpReq = checkArpRequestQueue(target_ip)){
		sendArpWaitPackets(sr,arpReq,target_addr);
	}
}


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


    printf("*** -> Received packet of length %d\n",len);

    struct sr_ethernet_hdr *ethHdr = (struct sr_ethernet_hdr *) packet;
    uint16_t ethType = ntohs(ethHdr->ether_type);


    /*
     * ARP Case.
     */
    if(ethType == ETHERTYPE_ARP){
    	struct sr_arphdr * arpHdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

    	if(ntohs(arpHdr->ar_hrd) != ARPHDR_ETHER){
    		printf("Invalid ARP Hardware Type. Dropping packet.\n");
    		return;
    	}
    	if(ntohs(arpHdr->ar_pro) != ETHERTYPE_IP){
    		printf("Invalid ARP Protocol Type. Dropping packet.\n");
    		return;
    	}
    	struct sr_if* dst_if = destInterfaceCheck(sr, arpHdr->ar_tip);
    	if(!dst_if){
    		printf("Invalid ARP Message: Wrong Destination.\n");
    		return;
    	}
    	if(ntohs(arpHdr->ar_op) == ARP_REQUEST){
    		struct sr_if * target_if = destInterfaceCheck(sr, arpHdr->ar_tip);
    		form_arp_reply_packet(ethHdr, arpHdr, target_if);
//    		print_packet(packet,len);
    		sr_send_packet(sr, packet, len, interface);
    	}
    	if(ntohs(arpHdr->ar_op) == ARP_REPLY){
    		handle_arp_reply_packet(sr, ethHdr, arpHdr);
    	}
    }
    /*
     * IPv4 Case.
     */
    else if(ethType == ETHERTYPE_IP){
    	struct ip * ip_packet = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    	uint16_t checksum_rcvd = ntohs(ip_packet->ip_sum);
    	ip_packet->ip_sum = 0;
    	unsigned int ip_hdr_len = ip_packet->ip_v * ip_packet->ip_hl;
    	uint16_t checksum_cptd = compute_checksum((uint16_t*)ip_packet, ip_hdr_len);
    	if(checksum_rcvd != checksum_cptd){
    		printf("IP Header Checksum is incorrect. Dropping packet.\n");
    		return;
    	}
    	struct sr_if* target_if = destInterfaceCheck(sr, (ip_packet->ip_dst).s_addr);


    	/*
    	 * Case when received a packet that has exceeded time.
    	 */
    	if((ip_packet->ip_ttl -= 1) == 0){
    		if (ip_packet->ip_p == IPPROTO_ICMP) {
    			struct icmp_hdr *icmp = (struct icmp_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + ip_hdr_len);
    			if (icmp->type == ICMP_DEST_UNREACH || icmp->type == ICMP_TIME_EXCEEDED)
    				return;
    		}
    		unsigned int total_length; uint8_t *err_packet; struct sr_ethernet_hdr *ether_hdr;
    		struct ip *ip_hdr; struct icmp_hdr *icmp_hdr;
    		ip_packet->ip_ttl += 1;
    		total_length = init_icmp_err(&err_packet, ip_packet, ip_hdr_len, &ether_hdr, &ip_hdr, &icmp_hdr);

    		struct sr_if* src_if = sr_get_interface(sr, interface);

    		init_icmp_ethernet_hdr(ether_hdr, src_if->addr, ethHdr->ether_shost);
    		init_icmp_ip_hdr(ip_hdr, ip_hdr_len, src_if->ip, (ip_packet->ip_src).s_addr);
    		init_icmp_icmp_hdr_data(icmp_hdr, ICMP_TIME_EXCEEDED, 0, ip_packet, ip_hdr_len + ICMP_DATA_LEN);
//    		for(int i = 0; i < total_length; i++)
//    			printf("%X ",*(err_packet+i));
//    		printf("\n");
    		fprintf(stderr,"TIME EXCEEDED PACKET ARRIVED. SENDING ICMP PACKET TO THE SENDER.\n");
    		sr_send_packet(sr,err_packet,total_length,interface);
    		free(err_packet);
    		err_packet = 0;
    		return;
    	}
    	/*
    	 * Case when the destination is one of the interfaces.
    	 */
    	if(target_if){
    		/*
    		 * ICMP Request Case.
    		 */
			if(ip_packet->ip_p == IPPROTO_ICMP){
				struct icmp_hdr * icmp = (struct icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + ip_hdr_len);
				if(icmp->type == ICMP_ECHO_REQUEST){
					uint16_t sum_rcvd = ntohs(icmp->sum);
					icmp->sum = 0;
					uint16_t sum_cptd = compute_checksum((uint16_t *)icmp, ntohs(ip_packet->ip_len) - ip_hdr_len);
					if(sum_rcvd != sum_cptd){
						printf("ICMP Checksum is incorrect. Dropping packet.\n");
						return;
					}
					form_icmp_reply_packet(packet);
					sr_send_packet(sr, packet, len, interface);
					return;
				}
			}
			/*
			 * TCP or UDP Case.
			 * Drop the packet and send ICMP Port Unreachable packet.
			 */
			else if(ip_packet->ip_p == TCP || ip_packet->ip_p == UDP){
				unsigned int total_length; uint8_t *err_packet; struct sr_ethernet_hdr *ether_hdr;
				struct ip *ip_hdr; struct icmp_hdr *icmp_hdr;
				ip_packet->ip_ttl += 1;
				total_length = init_icmp_err(&err_packet, ip_packet, ip_hdr_len, &ether_hdr, &ip_hdr, &icmp_hdr);
				struct sr_if* src_if = sr_get_interface(sr, interface);
				init_icmp_ethernet_hdr(ether_hdr, src_if->addr, ethHdr->ether_shost);
				init_icmp_ip_hdr(ip_hdr, ip_hdr_len, src_if->ip, (ip_packet->ip_src).s_addr);
				init_icmp_icmp_hdr_data(icmp_hdr,ICMP_DEST_UNREACH,ICMP_PORT_UNREACH,ip_packet,ip_hdr_len + ICMP_DATA_LEN);
				sr_send_packet(sr,err_packet,total_length,interface);
				printf("TCP / UDP Packet arrived. SENT ICMP DESTINATION (PORT) UNREACHABLE PACKET\n");
				free(err_packet);
				err_packet = 0;
				return;
			}
    	}
    	/*
    	 * Otherwise, forward the packet by looking up in the routing table.
    	 */
		else{

			uint32_t dst_ip = (ip_packet->ip_dst).s_addr;
		    struct sr_rt *nexthop_rt = search_rt(sr, (uint8_t*) &dst_ip);
		    uint32_t nexthop_ip = (nexthop_rt->gw).s_addr;

		    struct sr_if* nIf = sr_get_interface(sr, nexthop_rt->interface);

		    struct arp_request* arpReq;

		    struct arp_cache* arpCache;

		    if(arpCache = checkArpCacheQueue(nexthop_ip)){
		    	memcpy(ethHdr->ether_dhost,arpCache->addr,ETHER_ADDR_LEN);
		    	memcpy(ethHdr->ether_shost,nIf->addr,ETHER_ADDR_LEN);
		    	ip_packet->ip_ttl -= 1;
		    	ip_packet->ip_sum = 0;
		    	ip_packet->ip_sum = htons(compute_checksum((uint16_t *)ip_packet,ip_hdr_len));
		    	sr_send_packet(sr,packet,len,nIf->name);
		    }
		    else{
		    	if(arpReq = checkArpRequestQueue(nexthop_ip)){
					addArpRequest(packet, len, nexthop_ip, nIf);
				}
				else{
					unsigned int nSize = sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arphdr);
					uint8_t* reqPacket = (uint8_t*)malloc(nSize);
					form_arp_request_packet((struct sr_ethernet_hdr*)reqPacket, (struct sr_arphdr*)(reqPacket+sizeof(struct sr_ethernet_hdr)), nIf,nexthop_ip);

					sr_send_packet(sr,reqPacket, nSize, nIf->name);
					addArpRequest(packet, len, nexthop_ip, nIf);
				}
		    }

		}

    }

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



