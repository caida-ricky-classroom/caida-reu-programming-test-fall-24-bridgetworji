#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>  //changed this line to work on MacOS system
#define MAX_OCTET 256

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header; //MacOS changes cont.
    int packet_count = 0;
    int octetCounts[MAX_OCTET] = {0}; //counting the last octet values

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        ip_header = (struct ip*)(packet + sizeof(struct ether_header)); //macOS changes continued 

        unsigned char* ip_bytes = (unsigned char*)&ip_header->ip_dst.s_addr;
        unsigned int lastOctet = ip_bytes[3];  // The last octet is the 4th byte
        octetCounts[lastOctet]++; //increment count of last octet
    }


    for (int i=0; i < MAX_OCTET; i++) {
        if (octetCounts[i] > 0) {
            printf("Last octet %d: %03d\n", i, octetCounts[i]%1000);
        }
    }

    pcap_close(handle);
    return 0;
}
