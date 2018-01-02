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
#include <stdlib.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq * req)
{
  if(!sr || !req)
    return;

  if (difftime(time(NULL), req->sent) > 1.0)
  {
    if(req->times_sent >= 5)
    {
      /* send ICMP host unreachable to source addr of all packets waiting on this request */
      struct sr_packet * curr = req->packets;
      if (curr)
      {
        (void)construct_icmp_h_unreach_and_send(sr, curr->buf);
        while(curr->next)
        {
          curr = curr->next;
          (void)construct_icmp_h_unreach_and_send(sr, curr->buf);
        }
      }
      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    {
      /* send ARP request */
      int retval = construct_arp_buf_and_send(sr, req);

      printf("RETURN VALUE: %d\n", retval);

      req->sent = time(NULL);
      req->times_sent++;
    }
  }
}

int construct_icmp_h_unreach_and_send(struct sr_instance* sr, uint8_t * buf)
{
  uint8_t orig_buf[IP_MAXPACKET];
  memcpy(orig_buf, buf, sizeof(orig_buf));

  sr_ethernet_hdr_t * ehdr = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(buf+sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t * icmp_hdr = (sr_icmp_t11_hdr_t *) malloc(sizeof(sr_icmp_t11_hdr_t));

  uint8_t * shost_copy[ETHER_ADDR_LEN];
  memcpy(shost_copy, ehdr->ether_shost, sizeof(shost_copy));
  memcpy(ehdr->ether_shost, ehdr->ether_dhost, sizeof(ehdr->ether_shost));
  memcpy(ehdr->ether_dhost, shost_copy, sizeof(ehdr->ether_dhost));

  printf("PRINTING IP HEADER --------- \n\n");
  print_hdr_ip(buf+sizeof(sr_ethernet_hdr_t));
  
  ip_hdr->ip_ttl = 64;

  /* Longest prefix match with destination IP address */

  struct sr_rt * curr = sr->routing_table;
  struct sr_rt * longest_match = NULL;
  while (curr->next != NULL)
  {
    if ((ip_hdr->ip_src & curr->mask.s_addr) == curr->dest.s_addr)
    {
      if (longest_match == NULL)
        longest_match = curr;
      else if (longest_match != NULL && longest_match->mask.s_addr < curr->mask.s_addr)
        longest_match = curr;
    }
    curr = curr->next;
  }
  if (longest_match == NULL)
  {
    if ((ip_hdr->ip_src & curr->mask.s_addr) == curr->dest.s_addr)
      longest_match = curr;
    else /* No match found in routing table */
    {
      fprintf(stderr, "No match in routing table -- LPM for ICMP host unreachable!\n");
      return 1; /* this case should never occur */
    }
  }
  fprintf(stdout, "MATCHED INTERFACE NAME: %s\n", longest_match->interface);
  /* Longest prefix match complete! */

  /* set source and dest IP addresses in IP header */
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = sr_get_interface(sr, longest_match->interface)->ip;

  ip_hdr->ip_len = htons(sizeof(*ip_hdr)+sizeof(*icmp_hdr));

  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(*ip_hdr));
  
  icmp_hdr->icmp_type = 3;
  icmp_hdr->icmp_code = 1;
  icmp_hdr->unused = 0;
  memcpy(icmp_hdr->data, orig_buf+sizeof(sr_ethernet_hdr_t), sizeof(icmp_hdr->data));

  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(*icmp_hdr));  
  
  /*copy headers into int buffer*/
  uint8_t buffer[sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t)];
  memcpy(buffer, ehdr, sizeof(sr_ethernet_hdr_t));
  memcpy(buffer+sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));
  memcpy(buffer+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

  /*send packet*/
  int retval = sr_send_packet(sr, buffer, sizeof(*ehdr)+sizeof(*ip_hdr)+sizeof(*icmp_hdr), 
                              longest_match->interface);

  return retval;
}

int construct_icmp_net_unreach_and_send(struct sr_instance* sr, uint8_t * buf, char * iface)
{
  uint8_t orig_buf[IP_MAXPACKET];
  memcpy(orig_buf, buf, sizeof(orig_buf));

  sr_ethernet_hdr_t * ehdr = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(buf+sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t * icmp_hdr = (sr_icmp_t11_hdr_t *) malloc(sizeof(sr_icmp_t11_hdr_t));

  uint8_t * shost_copy[ETHER_ADDR_LEN];
  memcpy(shost_copy, ehdr->ether_shost, sizeof(shost_copy));
  memcpy(ehdr->ether_shost, ehdr->ether_dhost, sizeof(ehdr->ether_shost));
  memcpy(ehdr->ether_dhost, shost_copy, sizeof(ehdr->ether_dhost));
  
  ip_hdr->ip_ttl = 64;

  /* set source and dest IP addresses in IP header */
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = sr_get_interface(sr, iface)->ip;

  ip_hdr->ip_len = htons(sizeof(*ip_hdr)+sizeof(*icmp_hdr));

  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(*ip_hdr));
  
  icmp_hdr->icmp_type = 3;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->unused = 0;
  memcpy(icmp_hdr->data, orig_buf+sizeof(sr_ethernet_hdr_t), sizeof(icmp_hdr->data));

  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(*icmp_hdr));  
  
  /*copy headers into int buffer*/
  uint8_t buffer[sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t)];
  memcpy(buffer, ehdr, sizeof(sr_ethernet_hdr_t));
  memcpy(buffer+sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));
  memcpy(buffer+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

  /*send packet*/
  int retval = sr_send_packet(sr, buffer, sizeof(*ehdr)+sizeof(*ip_hdr)+sizeof(*icmp_hdr), iface);

  return retval;
}

int construct_arp_buf_and_send(struct sr_instance* sr, struct sr_arpreq * req)
{
  /*get broadcast address*/
  uint8_t BROADCAST_ADDR[ETHER_ADDR_LEN];
  int index;
  
  for(index = 0; index < ETHER_ADDR_LEN; index++)
  {
    BROADCAST_ADDR[index] = 255;
  }
  /* broadcast address setup complete */

  struct sr_if * matching_if = sr_get_interface(sr, req->packets->iface);
  sr_ethernet_hdr_t * ehdr = (sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t));
  sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) malloc(sizeof(sr_arp_hdr_t));

  /*setup ethernet header*/
  memcpy(ehdr->ether_dhost, BROADCAST_ADDR, sizeof(ehdr->ether_dhost));
  memcpy(ehdr->ether_shost, matching_if->addr, sizeof(ehdr->ether_shost));
  ehdr->ether_type = htons(ethertype_arp);

  /*setup arp header*/
  arp_hdr->ar_hrd = htons(1); /*ethernet*/
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = 0x06;
  arp_hdr->ar_pln = 0x04;
  arp_hdr->ar_op = htons(1); /*arp request*/
  memcpy(arp_hdr->ar_sha, matching_if->addr, sizeof(arp_hdr->ar_sha));
  arp_hdr->ar_sip = matching_if->ip;
  memcpy(arp_hdr->ar_tha, BROADCAST_ADDR, sizeof(arp_hdr->ar_tha));
  arp_hdr->ar_tip = req->ip;

  /*copy headers into int buffer*/
  uint8_t buf[sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t)];
  memcpy(buf, ehdr, sizeof(sr_ethernet_hdr_t));
  memcpy(buf+sizeof(sr_ethernet_hdr_t), arp_hdr, sizeof(sr_arp_hdr_t));

  int retval = sr_send_packet(sr, buf, sizeof(*ehdr)+sizeof(*arp_hdr), matching_if->name);

  /*free memory*/
  free(ehdr);
  free(arp_hdr);

  return retval;
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

  printf("*** -> Received packet of length %d \n",len);

  int minlength = sizeof(sr_ethernet_hdr_t);
  if(len < minlength)
  {
    fprintf(stderr, "ETHERNET header insufficient length!\n");
    return;
  }
  else if (len > IP_MAXPACKET)
  {
    fprintf(stderr, "Packet length too long!\n");
    return;
  }
  print_hdr_eth(packet);

  uint8_t packet_copy[IP_MAXPACKET];
  memcpy(packet_copy, packet, len);
  
  uint16_t ethtype = ethertype(packet);
  switch (ethtype)
  {
    case ethertype_ip:
      printf("IP packet: \n");
      print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t)); 

      /* SANITY CHECK -- minimum length and checksum validity */
      minlength += sizeof(sr_ip_hdr_t);
      if (len < minlength)
      {
        fprintf(stderr, "IP header insufficient length!\n");
        return;
      }
      
      uint16_t ip_sum_copy;
      sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      ip_sum_copy = ip_hdr->ip_sum;
      ip_hdr->ip_sum = 0;
      if (cksum(ip_hdr, sizeof(*ip_hdr))/*ntohs(ip_hdr->ip_len))*/ != ip_sum_copy)
      {
        fprintf(stderr, "IP checksum invalid!\n"); 
        return;
      }
      fprintf(stdout, "CHECKSUM VALID!\n");
      /* SANITY CHECK COMPLETE */

      /* Check if packet is destined for one of our IP addresses */
      struct sr_if * curr_if = sr_get_interface(sr, interface);
      while (ip_hdr->ip_dst != curr_if->ip && curr_if->next != NULL)
      {
        curr_if = curr_if->next;
      }
      /* Packet IS destined for one of our IP addresses */
      if(curr_if->ip == ip_hdr->ip_dst)
      {
        printf("THIS IP PACKET IS DESTINED FOR US!\n");
        
        /* Is the payload ICMP ?  */
        if (ip_hdr->ip_p == ip_protocol_icmp)
        {
          sr_icmp_t11_hdr_t * icmp_hdr = 
            (sr_icmp_t11_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

          /* Check if it is an ICMP request  */
          if (icmp_hdr->icmp_type == 8)
          {
            /* Is the checksum valid? */ 
            uint16_t icmp_sum_copy = icmp_hdr->icmp_sum;
            icmp_hdr->icmp_sum = 0;
            if (cksum(icmp_hdr, ntohs(ip_hdr->ip_len)-sizeof(*ip_hdr)) != icmp_sum_copy)
            {
              printf("ICMP checksum invalid!\n");
              return;
            }
            /* Checksum is valid! */

            /* setup ICMP reply */ 
            sr_ethernet_hdr_t * ehdr = (sr_ethernet_hdr_t *)packet;
            uint8_t shost_copy[ETHER_ADDR_LEN];
            memcpy(shost_copy, ehdr->ether_shost, sizeof(shost_copy));
            memcpy(ehdr->ether_shost, ehdr->ether_dhost, sizeof(ehdr->ether_shost));
            memcpy(ehdr->ether_dhost, shost_copy, sizeof(ehdr->ether_dhost));

            uint32_t ip_src_cpy = ip_hdr->ip_src;
            ip_hdr->ip_src = ip_hdr->ip_dst;
            ip_hdr->ip_dst = ip_src_cpy;
            ip_hdr->ip_ttl = 64;

            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(*ip_hdr));

            icmp_hdr->icmp_type = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len)-sizeof(*ip_hdr));

            /* send packet */
            int retval = sr_send_packet(sr, packet, len, interface);
          }
        }
        /* Check if it contains a TCP or UDP payload */
        else if(ip_hdr->ip_p == ip_protocol_udp || ip_hdr->ip_p == ip_protocol_tcp)
        {
          sr_ethernet_hdr_t * ehdr = (sr_ethernet_hdr_t *)packet;
          uint8_t shost_copy[ETHER_ADDR_LEN];
          memcpy(shost_copy, ehdr->ether_shost, sizeof(shost_copy));
          memcpy(ehdr->ether_shost, ehdr->ether_dhost, sizeof(ehdr->ether_shost));
          memcpy(ehdr->ether_dhost, shost_copy, sizeof(ehdr->ether_dhost));

         
          uint32_t ip_src_cpy = ip_hdr->ip_src;
          ip_hdr->ip_src = ip_hdr->ip_dst;
          ip_hdr->ip_dst = ip_src_cpy;
          ip_hdr->ip_ttl = 64;
          ip_hdr->ip_p = ip_protocol_icmp;
          ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t));

          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, sizeof(*ip_hdr));


          sr_icmp_t11_hdr_t * icmp_hdr = (sr_icmp_t11_hdr_t *)malloc(sizeof(sr_icmp_t11_hdr_t));     
          icmp_hdr->icmp_type = 3;
          icmp_hdr->icmp_code = 3;
          icmp_hdr->unused = 0;
          memcpy(icmp_hdr->data, packet_copy+sizeof(sr_ethernet_hdr_t), sizeof(icmp_hdr->data));

          icmp_hdr->icmp_sum = 0;
          icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(*icmp_hdr));

          /*copy headers into int buffer*/
          uint8_t buf[sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t)];
          memcpy(buf, ehdr, sizeof(sr_ethernet_hdr_t));
          memcpy(buf+sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));
          memcpy(buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
          
          /* send packet */
          int retval = sr_send_packet(sr, buf, 
            sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t), interface);
        }
      }
      /* Packet is NOT destined for one of our IP addresses */
      else
      {
        /* Decrement TTL and recompute checksum */ 
        ip_hdr->ip_ttl -= 1;
        if (ip_hdr->ip_ttl == 0) /* send ICMP time exceeded */
        {
          /* setup ethernet header */
          sr_ethernet_hdr_t * ehdr = (sr_ethernet_hdr_t *)packet;
          uint8_t shost_copy[ETHER_ADDR_LEN];
          memcpy(shost_copy, ehdr->ether_shost, sizeof(shost_copy));
          memcpy(ehdr->ether_shost, ehdr->ether_dhost, sizeof(ehdr->ether_shost));
          memcpy(ehdr->ether_dhost, shost_copy, sizeof(ehdr->ether_dhost));
         
          /* setup IP header */
          ip_hdr->ip_dst = ip_hdr->ip_src;
          ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
          ip_hdr->ip_ttl = 64;
          ip_hdr->ip_p = ip_protocol_icmp;
          ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t));

          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, sizeof(*ip_hdr));

          /* setup ICMP header */
          sr_icmp_t11_hdr_t * icmp_hdr = (sr_icmp_t11_hdr_t *)malloc(sizeof(sr_icmp_t11_hdr_t));     
          icmp_hdr->icmp_type = 11;
          icmp_hdr->icmp_code = 0;
          icmp_hdr->unused = 0;
          memcpy(icmp_hdr->data, packet_copy+sizeof(sr_ethernet_hdr_t), sizeof(icmp_hdr->data));

          icmp_hdr->icmp_sum = 0;
          icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(*icmp_hdr));

          /*copy headers into int buffer*/
          uint8_t buf[sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t)];
          memcpy(buf, ehdr, sizeof(sr_ethernet_hdr_t));
          memcpy(buf+sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));
          memcpy(buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
          
          /* send packet */
          int retval = sr_send_packet(sr, buf, 
            sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t), interface);
        }

        ip_hdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(*ip_hdr));

        /* Longest prefix match with destination IP address */
      
        struct sr_rt * curr = sr->routing_table;
        struct sr_rt * longest_match = NULL;
        while (curr->next != NULL)
        {
          if ((ip_hdr->ip_dst & curr->mask.s_addr) == curr->dest.s_addr)
          {
            if (longest_match == NULL)
              longest_match = curr;
            else if (longest_match != NULL && longest_match->mask.s_addr < curr->mask.s_addr)
              longest_match = curr;
          }
          curr = curr->next;
        }
        if (longest_match == NULL)
        {
          if ((ip_hdr->ip_dst & curr->mask.s_addr) == curr->dest.s_addr)
            longest_match = curr;
          else /* No match found in routing table */
          {
            fprintf(stderr, "No match in routing table!\n");
            (void)construct_icmp_net_unreach_and_send(sr, packet, interface);
            return;
          }
        }
        fprintf(stdout, "MATCHED INTERFACE NAME: %s\n", longest_match->interface);
        /* Longest prefix match complete! */

        /* Check ARP cache for next-hop MAC address */
        struct sr_arpentry * arp_entry = sr_arpcache_lookup(&(sr->cache), longest_match->gw.s_addr);
        if (arp_entry)
        {
          printf("ARP cache entry found!\n");
          /* send ARP packet using IP->MAC mapping in cache */
          
          /* modify ETHERNET header */
          sr_ethernet_hdr_t * ehdr = (sr_ethernet_hdr_t *)packet;
          memcpy(ehdr->ether_dhost, arp_entry->mac, sizeof(ehdr->ether_dhost));
          memcpy(ehdr->ether_shost, sr_get_interface(sr, longest_match->interface)->addr, 
                 sizeof(ehdr->ether_shost));
          int val = sr_send_packet(sr, packet, len, longest_match->interface); 
          free(arp_entry);
        }
        else
        {
          printf("Not found in ARP cache.\n");
          /* Add packet to ARP cache queue */ 
          struct sr_arpreq * req = sr_arpcache_queuereq(&(sr->cache), 
                                    longest_match->gw.s_addr, packet, len, longest_match->interface);
          printf("longest_match->gw.s_addr is: %d\n", longest_match->gw.s_addr);
          /*struct sr_if * matching_if = sr_get_interface(sr, longest_match->interface);*/
          if(req)
          {
            printf("Request added to req queue properly!\n");
          }
          handle_arpreq(sr, req);
        }

        printf("This IP packet is NOT destined for us.\n");
      }
      
      break;
    
    case ethertype_arp:
      printf("ARP packet: \n");
      print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
      sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      if (ntohs(arp_hdr->ar_op) == arp_op_request) /* opcode is 1 -- request */
      {
        /* send ARP reply if target IP address is router's interface IP */         
        if (arp_hdr->ar_tip == sr_get_interface(sr, interface)->ip)
        {
          int val = sr_send_arp_reply(sr, packet, len, interface);
          fprintf(stdout, "\nRETURN VAL ==> %d\n", val);
        }
      }
      else if (ntohs(arp_hdr->ar_op) == arp_op_reply) /* opcode is 2 -- reply */
      {
        printf("\n\n\nRECEIVED ARP REPLY!!!\n");
        pthread_mutex_lock(&(sr->cache.lock));
        struct sr_arpreq * req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip); 
        pthread_mutex_unlock(&(sr->cache.lock));
        if (req)
        {
          printf("IN REQ IF STATEMENT\n");
          struct sr_packet * pkts = req->packets;
          if (pkts)
          {
            printf("SENDING PACKETS\n");
            /* modify ETHERNET header */
            sr_ethernet_hdr_t * ehdr = (sr_ethernet_hdr_t *)pkts->buf;
            memcpy(ehdr->ether_dhost, arp_hdr->ar_sha, sizeof(ehdr->ether_dhost));
            memcpy(ehdr->ether_shost, arp_hdr->ar_tha, sizeof(ehdr->ether_shost));
            
            int retval = sr_send_packet(sr, pkts->buf, pkts->len, pkts->iface);
            while (pkts->next)
            {
              pkts = pkts->next;
              
              /* modify ETHERNET header */
              ehdr = (sr_ethernet_hdr_t *)pkts->buf;
              memcpy(ehdr->ether_dhost, arp_hdr->ar_sha, sizeof(ehdr->ether_dhost));
              memcpy(ehdr->ether_shost, arp_hdr->ar_tha, sizeof(ehdr->ether_shost));
              
              retval = sr_send_packet(sr, pkts->buf, pkts->len, pkts->iface);
            }
          }
          sr_arpreq_destroy(&(sr->cache), req);
        }
      }
      break;

    default:
      printf("Did not match any packet type!\n");
      break;
  }


}/* end sr_ForwardPacket */

int sr_send_arp_reply(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  
/*
DEBUG ****
  printf("\n\nBEFORE MODIFICATION: \n");
  print_hdr_eth(packet); 
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
DEBUG ****
*/

  /* modify ETHERNET header */
  sr_ethernet_hdr_t * ehdr = (sr_ethernet_hdr_t *)packet;
  memcpy(ehdr->ether_dhost, ehdr->ether_shost, sizeof(ehdr->ether_dhost));
  memcpy(ehdr->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(ehdr->ether_shost));

  /* modify ARP header */
  sr_arp_hdr_t * ahdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  ahdr->ar_op = htons(2);
  memcpy(ahdr->ar_tha, ahdr->ar_sha, sizeof(ahdr->ar_sha));
  memcpy(ahdr->ar_sha, sr_get_interface(sr, interface)->addr, sizeof(ahdr->ar_sha));

  uint32_t temp = ahdr->ar_sip;
  ahdr->ar_sip = ahdr->ar_tip;
  ahdr->ar_tip = temp;

/* 
DEBUG ***********
  printf("\n\nAFTER MODIFICATION: \n");
  print_hdr_eth(packet);
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
DEBUG ***********
*/

  /* send ARP reply with modified packet */
  int val = sr_send_packet(sr, packet, len, interface); 

  return val;
}


