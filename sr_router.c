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


    uint8_t* dest = malloc(6*sizeof(uint8_t));
    uint8_t* src = malloc(6*sizeof(uint8_t));
    uint8_t* ethType = malloc(2*sizeof(uint8_t));

	uint8_t* nPacket = malloc(len*sizeof(uint8_t));

	memcpy(nPacket, packet, len);

    memcpy(dest, packet, 6);
    memcpy(src, packet+6, 6);
    memcpy(ethType, packet+12, 2);

    while(strcmp(sr_if->name,interface)){
        printf("%s\n",sr_if->name);
       	sr_if = sr_if->next;
    }

    if(!strcmp((unsigned char*)dest, sr_if->addr)){

		switch(*ethType){
			case 0x8:
				/// ARP Case
				if(*(ethType+1) == 0x6){
					memcpy(nPacket,src,6);
					memcpy(nPacket+6,sr_if->addr,6);
					*(nPacket+20) = 0x00;
					*(nPacket+21) = 0x02;
					memcpy(nPacket+22,sr_if->addr,6);
					*(uint32_t*)(nPacket+28) = sr_if->ip;
	//    			printf("%X\n",sr_if->ip);
	//    			for(int i = 0; i < 4; i++)
	//    				printf("%X ",*(nPacket+28+i));
	//    			printf("\n");
					memcpy(nPacket+32,packet+22,6);
					memcpy(nPacket+38,packet+28,4);

					sr_send_packet(sr,nPacket,len,sr_if->name);
				}
				/// Standard IPv4 Case
				else if(*(ethType+1) == 0x0){

					while(strcmp(sr_if->name,interface)){
						printf("%s\n",sr_if->name);
						sr_if = sr_if->next;
					}
					memcpy(nPacket,src,6);
					memcpy(nPacket+6,sr_if->addr,6);

					/// ICMP Protocol Case
					if(*(packet+0x17) == 0x1){
						*(uint32_t*)(nPacket+0x1a) = sr_if->ip;
	//    				printf("%X\n",sr_if->ip);
	//    				for(int i = 0; i < 4; i++)
	//    					printf("%X ",*(nPacket+0x1a+i));
	//    				printf("\n");
						memcpy(nPacket+0x1e,packet+0x1a,4);
						*(nPacket+0x22) = 0x0;
					}

					/// UDP Protocol Case
					if(*(packet+0x17) == 0x11){
						printf("DO SOMETHING");
					}

					int hLen = (*(packet+0x0e) >> 4) * (*(packet+0x0e) & 0x0F);
					*(nPacket+0x18) = 0;
					*(nPacket+0x19) = 0;
					uint16_t checksum = compute_checksum(nPacket+0x0e,hLen);
					*(nPacket+0x18) = (checksum & 0xFF00) >> 8;
					*(nPacket+0x19) = checksum & 0x00FF;

					*(nPacket+0x24) = 0;
					*(nPacket+0x25) = 0;
					checksum = compute_checksum(nPacket+0x22,len-14-hLen);
					*(nPacket+0x24) = (checksum & 0xFF00) >> 8;
					*(nPacket+0x25) = checksum & 0x00FF;
					sr_send_packet(sr,nPacket,len,sr_if->name);
				}
				break;
			default:
				break;
		}
    }

//    for(int i = 0; i < len; i++)
//    	printf("%X ",*(nPacket+i));
//    printf("\n");

    printf("*** -> Received packet of length %d\n",len);

}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

uint16_t compute_checksum(uint8_t* header, int length){
	uint32_t sum = 0;

	while(length > 1){
//		printf("ADDING: %X\n",htons(*((uint16_t*) header)));
		sum = sum + htons(*((uint16_t*) header)++);
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

