#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define MAX_LEN 100000
#define ARP_LEN 42
#define ICMP_LEN 98
#define ETHERTYPE_IP 0x0800

/* Address Lookup using Trie */
struct trie {
	struct route_table_entry *route;
	struct trie *first;
	struct trie *second;
};

/* Head of Trie */
struct trie *trie;

/* Deferred packets waiting for an ARP Reply */
queue deferred_packets;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

/* Routing table */

struct route_table_entry *route_table;

int rtable_len;

uint32_t set_highest_bit(uint32_t value) {
	return value | 0x80000000;
}

/* Add a node to the Trie */
void add_trie_node(struct route_table_entry *entry)
{
	struct trie *current = NULL;
	uint32_t current_mask = 0;
	int bit_index = 31;

	if (trie == NULL) {
		trie = calloc(1, sizeof(struct trie));
		DIE(trie == NULL, "memory");
	}

	current = trie;

	while (1) {
		if (current_mask == ntohl(entry->mask)) {
			current->route = entry;
			break;
		}

		int bit = (ntohl(entry->prefix) >> bit_index) & 1;

		if (!(bit & 1)) {
			if (! current->first) {
				current->first = calloc(1, sizeof(struct trie));
				DIE(current->first == NULL, "memory");
			}
			current = current->first;
		} else {
			if (!current->second) {
				current->second = calloc(1, sizeof(struct trie));
				DIE(current->second == NULL, "memory");
			}
			current = current->second;
		}

		current_mask = set_highest_bit(current_mask >> 1);
		bit_index--;
	}
}



/* Returns a pointer to the best matching route, or NULL if there is no
 * matching route. */
struct route_table_entry *get_best_route(uint32_t destination)
{
	struct route_table_entry *match = NULL;
	struct trie *current_node = trie;
	int bit_index = 31;

	while (current_node != NULL && bit_index >= 0) {
		// dacă nodul curent conține o ruta, o salvez ca fiind cea mai buna pâna acum
		if (current_node->route != NULL) {
			match = current_node->route;
		}

		// extrag bitul la poziția curenta
		uint32_t ip_host = ntohl(destination);
		uint8_t bit;

		if (ip_host & (1 << bit_index)) {
			bit = 1;
		} else {
			bit = 0;
		}

		// alegurmatorul nod în functie de bit
		if (bit == 0) {
			current_node = current_node->first;
		} else {
			current_node = current_node->second;
		}

		bit_index--;
	}

	return match;
}


struct arp_table_entry *get_arp_table_entry(uint32_t ip_dest)
{
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip_dest) {
			struct arp_table_entry *entry = &arp_table[i];
			return entry;
		}
	}
	return NULL;
}

/* Returns 1 if the address is a broadcast second, else 0 */
int is_broadcast_address(uint8_t  *address)
{
	for (int i = 0; i < 6; i++) {
		if (*(address + i) != 255) {
			return 0;
		}
	}
	return 1;
}

/* Returns 1 if the addresses are identical, else 0 */
int is_equal_address(uint8_t  a1[6], uint8_t a2[6])
{
	int match = 1;
	for (int i = 0; i < 6 && match; i++) {
		if (*(a1 + i) != *(a2 + i)) {
			match = 0;
		}
	}
	return match;
}

/* Add the packet to the deferred queue & sends an ARP Request */
void send_ARP_Request(void *buf, struct route_table_entry *ip_entry)
{
	char arp_request[MAX_PACKET_LEN];

	// Pachetul se salvează în coada deferred_packets
	void *stopped_packet = malloc(ICMP_LEN);
	DIE(stopped_packet == NULL, "memory");
	memcpy(stopped_packet, buf, ICMP_LEN);
	queue_enq(deferred_packets, stopped_packet);

	// Header Ethernet
	struct ether_hdr *eth_hdr = (struct ether_hdr *)arp_request;
	eth_hdr->ethr_type = htons(ETHERTYPE_IP + 6); // ARP
	get_interface_mac(ip_entry->interface, eth_hdr->ethr_shost);

	memset(eth_hdr->ethr_dhost, 0xFF, 6);

	// Header ARP
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(arp_request + sizeof(struct ether_hdr));
	arp_hdr->hw_type = htons(1);           // Ethernet
	arp_hdr->proto_type = htons(ETHERTYPE_IP);   // IPv4
	arp_hdr->hw_len = 6;                   // MAC length
	arp_hdr->proto_len = 4;                // IP length
	arp_hdr->opcode = htons(1);            // Request

	// Sender MAC și IP
	get_interface_mac(ip_entry->interface, arp_hdr->shwa);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(ip_entry->interface));

	// Target MAC se lasă 0
	memset(arp_hdr->thwa, 0, 6);

	// IP căutat (next hop)
	arp_hdr->tprotoa = ip_entry->next_hop;

	// Trimite pachetul
	send_to_link(ARP_LEN, arp_request, ip_entry->interface);
}


/* Sends an ARP Reply with the wanted address */
void send_ARP_Reply(int interface, void *buf, uint8_t wanted_adr[6])
{
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

	// Setează opcode la "reply"
	arp_hdr->opcode = htons(2);

	// Schimbă MAC-urile: thwa <- shwa, shwa <- MAC-ul nostru
	uint8_t tmp_mac[6];
	memcpy(tmp_mac, arp_hdr->shwa, 6);
	memcpy(arp_hdr->thwa, tmp_mac, 6);
	memcpy(arp_hdr->shwa, wanted_adr, 6);

	// Schimbă IP-urile manual (sprotoa <-> tprotoa)
	uint32_t tmp_ip = arp_hdr->sprotoa;
	arp_hdr->sprotoa = arp_hdr->tprotoa;
	arp_hdr->tprotoa = tmp_ip;

	// Actualizează și headerul Ethernet
	for (int i = 0; i < 6; i++) {
		eth_hdr->ethr_shost[i] = arp_hdr->shwa[i];
		eth_hdr->ethr_dhost[i] = arp_hdr->thwa[i];
	}


	// Trimite răspunsul
	send_to_link(ARP_LEN, buf, interface);
}


/* Parse the ARP reply and send the packets from the waiting list */
void get_ARP_Reply(void *buf, int interface)
{
	struct arp_hdr *arp = (struct arp_hdr *)((char *)buf + sizeof(struct ether_hdr));

	// Creăm o nouă intrare pentru tabela ARP
	struct arp_table_entry new_entry;
	new_entry.ip = arp->sprotoa;
	for (int k = 0; k < 6; ++k)
		new_entry.mac[k] = arp->shwa[k];

	// Adăugăm în tabel
	arp_table[arp_table_len++] = new_entry;

	// Verificăm dacă avem pachete în așteptare
	queue temp_queue = create_queue();

	DIE(!temp_queue, "memory");

	while (!queue_empty(deferred_packets)) {

		char *pending_pkt = queue_deq(deferred_packets);
		struct ip_hdr *ip = (struct ip_hdr *)(pending_pkt + sizeof(struct ether_hdr));
		struct ether_hdr *eth = (struct ether_hdr *)pending_pkt;
		struct route_table_entry *match = get_best_route(ip->dest_addr);

		if (match != NULL && match->next_hop == new_entry.ip) {
			// Actualizăm antetul Ethernet
			for (int j = 0; j < 6; ++j) {
				eth->ethr_shost[j] = arp->thwa[j];
				eth->ethr_dhost[j] = arp->shwa[j];
			}
			eth->ethr_type = htons(ETHERTYPE_IP);

			send_to_link(98, pending_pkt, interface);
		} else {
			queue_enq(temp_queue, pending_pkt);
		}
	}

	// Actualizăm coada principală
	deferred_packets = temp_queue;
}


/* Sends an ICMP packet with an error message */
void ICMP_error(char *buf, int interface, uint8_t type)
{
	char new_packet[MAX_PACKET_LEN];

	struct ether_hdr *eth = (struct ether_hdr *) new_packet;

	char *ip_start = new_packet + sizeof(struct ether_hdr);
	struct ip_hdr *ip = (struct ip_hdr *) ip_start;

	char *icmp_start = ip_start + sizeof(struct ip_hdr);
	struct icmp_hdr *icmp = (struct icmp_hdr *) icmp_start;

	char *icmp_payload = icmp_start + sizeof(struct icmp_hdr);


	// Copiem 64 de octeți din pachetul original
	for (int i = 0; i < 64; ++i)
		icmp_payload[i] = buf[sizeof(struct ether_hdr) + i];

	// Completăm headerul Ethernet
	struct ether_hdr *original_eth = (struct ether_hdr *)buf;
	for (int i = 0; i < 6; ++i) {
		eth->ethr_dhost[i] = original_eth->ethr_shost[i];
		eth->ethr_shost[i] = original_eth->ethr_dhost[i];
	}
	eth->ethr_type = htons(ETHERTYPE_IP);  // IP

	// Completăm headerul IP
	struct ip_hdr *original_ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	memcpy(ip, original_ip, sizeof(struct ip_hdr));
	ip->source_addr = inet_addr(get_interface_ip(interface));
	ip->dest_addr = original_ip->source_addr;
	ip->ttl = 64;
	ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 64);
	ip->proto = IPPROTO_ICMP;
	ip->checksum = 0;
	ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

	uint16_t icmp_len = sizeof(struct icmp_hdr) + 64;
	icmp->mtype = type;
	icmp->mcode = 0;
	icmp->check = 0;
	icmp->check = 0;
	icmp->check = htons(checksum((uint16_t *)icmp, icmp_len));

	size_t packet_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 64;
	send_to_link(packet_len, new_packet, interface);

}

/* Sends an ICMP "Echo reply" packet */
void ICMP_echoREPLY(int interface, char *buf)
{
	uint8_t prev_ttl;
	uint8_t temp_eth[6];
	struct ether_hdr *eth = (struct ether_hdr *) buf;
	struct ip_hdr *ip = (struct ip_hdr *)((char *)eth + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp = (struct icmp_hdr *)((char *)ip + sizeof(struct ip_hdr));


	for (int i = 0; i < 6; ++i) {
		temp_eth[i] = eth->ethr_shost[i];
		eth->ethr_shost[i] = eth->ethr_dhost[i];
		eth->ethr_dhost[i] = temp_eth[i];
	}
	icmp->mtype = icmp->mcode = icmp->check = 0;

	icmp->check = htons(checksum((uint16_t*)icmp, ntohs(ip->tot_len) - sizeof(struct ip_hdr)));

	// Schimbăm adresele IP
	uint32_t temp_ip = ip->source_addr;
	ip->source_addr = ip->dest_addr;
	ip->dest_addr = temp_ip;

	// Actualizăm TTL-ul și recalculăm checksum-ul IP
	prev_ttl = ip->ttl;
	ip->ttl-=1;
	ip->checksum = (ip->checksum - (uint16_t)prev_ttl + (uint16_t)ip->ttl);

	send_to_link(ICMP_LEN, buf, interface);
}

int main(int argc, char *argv[])
{
	// Do not modify this line
	init(argv + 2, argc - 2);

	char buf[MAX_PACKET_LEN];
	/* Code to allocate the ARP and route tables */
	route_table = malloc(MAX_LEN * sizeof(struct route_table_entry));
	DIE(!route_table, "memory");

	arp_table = malloc(MAX_LEN * sizeof(struct arp_table_entry));
	DIE(!arp_table, "memory");

	/* Create the deferred packets queue */
	deferred_packets = create_queue();
	DIE(!deferred_packets, "memory");

	/* Create the Trie */
	rtable_len = read_rtable(argv[1], route_table);

	for(int i = 0; i < rtable_len; i++)
		add_trie_node(&route_table[i]);

	while (1) {

		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
		uint32_t inter_ip;
		size_t length;
		uint8_t interface_mac[6];
		int interface;

		interface = recv_from_any_link(buf, &length);

		DIE(interface < 0, "recv_from_any_links");


		get_interface_mac(interface, interface_mac);
		inter_ip = inet_addr(get_interface_ip(interface));


		if (!(is_equal_address(eth_hdr->ethr_dhost, interface_mac) ||
			  is_broadcast_address(eth_hdr->ethr_dhost))) {
			continue;
		}

		if (ntohs(eth_hdr->ethr_type) == ETHERTYPE_IP) {

			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
			struct route_table_entry *ip_entry;
			struct arp_table_entry *mac_entry;
			uint16_t initial_check = ip_hdr->checksum;
			ip_hdr->checksum = 0;
			ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));


			if (htons(checksum((uint16_t*) ip_hdr, sizeof(struct ip_hdr))) != initial_check)
				continue;

			if (ip_hdr->dest_addr == inter_ip) {
				ICMP_echoREPLY(interface, buf);
				continue;
			}

			uint16_t ttl_val = ip_hdr->ttl;

			if (ip_hdr->ttl <= 1) {
				ICMP_error(buf,interface,  11); // time exceeded
				continue;
			}

			ip_hdr->ttl -=1;


			ip_entry = get_best_route(ip_hdr->dest_addr);
			if (ip_entry == NULL) {
				ICMP_error(buf, interface, 3);
				continue;
			}


			uint32_t partial = ~initial_check;
			partial += (uint16_t)ip_hdr->ttl;
			partial += ~((uint16_t)ttl_val);
			ip_hdr->checksum = ~(partial) - 1;



			get_interface_mac(ip_entry->interface, eth_hdr->ethr_shost);

			int i = 0;
			mac_entry = NULL;
			while (i < arp_table_len) {
				if (arp_table[i].ip == ip_entry->next_hop) {
					struct arp_table_entry *entry = &arp_table[i];
					mac_entry = entry;
				}
				i++;
			}

			if (! mac_entry) {
				send_ARP_Request(buf, ip_entry);
				continue;
			}

			for (int i = 0; i < 6; i++) {
				eth_hdr->ethr_dhost[i] = mac_entry->mac[i];
			}


			send_to_link(length, buf, ip_entry->interface);

			continue;
		} else if (ntohs(eth_hdr->ethr_type) == (ETHERTYPE_IP + 6)) {
			struct arp_hdr *head;

			head = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

			if (ntohs(head->opcode) == 1 && head->tprotoa == inter_ip) {
				send_ARP_Reply(interface, buf, interface_mac);
			}

			else if (ntohs(head->opcode) == 2)
				get_ARP_Reply(buf, interface);
		}
	}
}