//Jaroslav Kvasnička - IPK - PROJ2 - sniffer packetů
//Převážně používané zdroje
//https://www.tcpdump.org
//https://www.winpcap.org/docs/docs_412/html/group__wpcap.html
//https://www.binarytides.com/packet-sniffer-code-c-linux/

//používané knihovny
#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>

//Inializace všech proměnných používaných ve funkci "main" a ""argument_parse
int interface_ok = 0;
int port_ok = 0;
int tcp_ok = 0;
int udp_ok = 0;
int arp_ok = 0;
int icmp_ok = 0;
int numm_ok = 0;
int packets_number = 1;

std::string interface = "";
int port = -1;

//https://www.tcpdump.org/pcap.html © 2010-2021 The Tcpdump Group. Designed by Luis MartinGarcia
// IP header
	struct sniff_ip {
		u_char ip_vhl;
		u_char ip_tos;
		u_short ip_len;
		u_short ip_id;
		u_short ip_off;
		u_char ip_ttl;
		u_char ip_p;
		u_short ip_sum;
		struct in_addr ip_src,ip_dst;
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)

	// TCP header
	typedef u_int tcp_seq;

  // TCP sniffing
	struct sniff_tcp {
		u_short th_sport;
		u_short th_dport;
		tcp_seq th_seq;
		tcp_seq th_ack;
		u_char th_offx2;
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
};

// UDP sniffing
struct sniff_udp {
  u_short sport;
  u_short dport;
  u_short len;
  u_short checksum;
};

// ICMP sniffing
struct sniff_icmp{
  u_short sport;
  u_short dport;
  u_short len;
  u_short checksum;
};

	// Ethernet header
  #define ETHER_ADDR_LEN	6
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN];
		u_char ether_shost[ETHER_ADDR_LEN];
		u_short ether_type;
	};




//Parsování argumentů
void argument_parse(int argc, char *argv[])
{
  for(int i = 1; i < argc; i++)
  {
    std::string arg = std::string(argv[i]);

		// Kontrola Interface || interface
    if(arg == "-i" && interface_ok == 0)
    {
      interface_ok = 1;
      std::string tmp = std::string(argv[i+1]);
      if(tmp != "-i" && tmp != "--interface" && tmp != "-p" && tmp != "--tcp" && tmp != "-t" && tmp != "--udp" && tmp != "-u" && tmp != "--arp" && tmp != "--icmp" && tmp != "-n"){
        interface = tmp;
        i++;
      }
    }
    else if(arg == "--interface" && interface_ok == 0)
    {
      interface_ok = 1;
      std::string tmp = std::string(argv[i+1]);
			// Pokud neobsahuje další prvek přepínač, obsahuje data
      if(tmp != "-i" && tmp != "--interface" && tmp != "-p" && tmp != "--tcp" && tmp != "-t" && tmp != "--udp" && tmp != "-u" && tmp != "--arp" && tmp != "--icmp" && tmp != "-n"){
        interface = tmp;
        i++;
      }
    }
    else if(arg == "-p" && port_ok == 0)
    {

      port_ok = 1;
      std::string tmp = std::string(argv[i+1]);
			// Pokud neobsahuje další prvek přepínač, obsahuje data
      if(tmp != "-i" && tmp != "--interface" && tmp != "-p" && tmp != "--tcp" && tmp != "-t" && tmp != "--udp" && tmp != "-u" && tmp != "--arp" && tmp != "--icmp" && tmp != "-n"){
        try
        {
            int tmpi = std::stoi(std::string(argv[i+1]));
            i++;
            if(tmpi < 0){
              fprintf(stderr, "Wrong port number");
              exit(1);
            }
            port = tmpi;
        }
        catch(std::exception)
        {
          fprintf(stderr, "Wrong port number");
          exit(1);
        }
      }
      else
      {
        fprintf(stderr," Missing port number");
        exit(1);
      }
    }
    else if(arg == "--tcp" && tcp_ok == 0)
    {
      tcp_ok = 1;
    }
    else if(arg == "-t" && tcp_ok == 0)
    {
        tcp_ok = 1;
    }
    else if(arg == "--udp" && udp_ok == 0)
    {
      udp_ok = 1;
    }
    else if(arg == "-u" && udp_ok == 0)
    {
      udp_ok = 1;
    }
    else if(arg == "--arp" && arp_ok == 0)
    {
      arp_ok = 1;
    }
    else if(arg == "--icmp" && icmp_ok == 0)
    {
      icmp_ok = 1;
    }
    else if(arg == "-n" && numm_ok == 0)
    {
      numm_ok == 1;
      std::string tmp = std::string(argv[i+1]);
			// Pokud neobsahuje další prvek přepínač, obsahuje data
      if(tmp != "-i" && tmp != "--interface" && tmp != "-p" && tmp != "--tcp" && tmp != "-t" && tmp != "--udp" && tmp != "-u" && tmp != "--arp" && tmp != "--icmp" && tmp != "-n"){
        try
        {
            int tmpi = std::stoi(std::string(argv[i+1]));
            i++;
            if(tmpi < 0){
              fprintf(stderr, "Wrong port number");
              exit(1);
            }
            packets_number = tmpi;
        }
        catch(std::exception)
        {
          fprintf(stderr, "Wrong number");
          exit(1);
        }
      }
      else
      {
        fprintf(stderr," Missing number");
        exit(1);
      }
    }
    else
    {
      fprintf(stderr, "FALSE ARGUMENTS");
      exit(1);
    }
  }
}


// Pokud je -i bez argumentu vytiskni seznam interfaců
void lookupdev(std::string interface, int interface_ok)
{
	// Zjistím zařízení, pokud neexistuje vypiš chybu
  char errbuf[PCAP_ERRBUF_SIZE];
  char *dev = pcap_lookupdev(errbuf);
  if(interface == "")
  {
    if(dev == nullptr)
    {
      fprintf(stderr, "No device found");
      exit(1);
    }
    printf("LIST: %s\n",dev);
    exit(0);
  }
  if(dev == nullptr)
  {
    fprintf(stderr,"No device found");
    exit(1);
  }
}

// https://www.tcpdump.org/pcap.html -section filtering traffic - © 2010-2021 The Tcpdump Group. Designed by Luis MartinGarcia
// pro každý přepínač vytvoř filtr
std::string make_filter(std::string filter)
{
  if(port == -1)
  {
    if(tcp_ok == 1)
    {
      filter = filter + "tcp || ";
    }
    if(udp_ok == 1)
    {
      filter = filter + "udp || ";
    }
    if(arp_ok == 1)
    {
      filter = filter + "arp || ";
    }
    if(icmp_ok == 1)
    {
      filter = filter + "icmp || ";
    }
		//https://www.cplusplus.com/reference/string/string/erase/
    filter.erase(filter.size()-4);
  }
  else
  {
    //https://stackoverflow.com/questions/4668760/converting-an-int-to-stdstring
    std::string porty = std::to_string(port);
    if(tcp_ok == 1)
    {
      filter = filter + "tcp port " + porty.c_str() + " || ";
    }
    if(udp_ok == 1)
    {
      filter = filter + "udp port " + porty.c_str() + " || ";
    }
    if(arp_ok == 1)
    {
      filter = filter + "arp port " + porty.c_str() + " || ";
    }
    if(icmp_ok == 1)
    {
      filter = filter + "icmp port " + porty.c_str() + " || ";
    }
		//https://www.cplusplus.com/reference/string/string/erase/
    filter.erase(filter.size()-4);
  }
  return filter;
}


// Vytiskni data v hex a ascii
// https://www.binarytides.com/packet-sniffer-code-c-linux/
void PrintData (u_char *data , int Size)
{
  int g = 0;
  int S = 16;
  for (; g < Size - S; g += S)
  {
		// První sloupec 0x0000
  	printf("0x%04x ", g);
  	printf(" ");
    int begin = g;
    int end = S + g;
		// Tisk hexa dat v packetu
    for (int i = begin; i < end; i++)
        printf("%02x ", data[i]);
    int rest = end - begin;
    if (rest < 16) {
        for (int i = 0; i < 16 - rest; i++)
            printf("   ");
    }
    printf(" ");
            begin = g;
            end = S + g;
						// Tisk Ascii dat v packetu
          for(int i = begin; i < end; i++)
          {
        if(isprint(data[i])) {
            printf("%c", data[i]);
        }
				// Pokud je neznámý znak, vypiš "."
        else
          	printf(".");
    	}
          printf("\n");
      }
}


//https://www.tcpdump.org/pcap.html
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	// Hlavička ethernetu má vždy 14B
  #define SIZE_ETHERNET 14
  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_tcp *tcp;
  const struct sniff_udp *udp;
  const struct sniff_icmp *icmp;
	// payload jsou data
  u_char *payload;
  u_int size_ip;
  u_int size_tcp;
  u_int size_udp;
  u_int size_arp;
  u_int size_icmp;

	in_addr addr_src;
  in_addr addr_dst;

	// https://www.tcpdump.org/pcap.html
  ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	// ICMP https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	// Nedokončeno
  if(ip->ip_p == 1)
  {
    size_icmp = 16;
    u_int sub = size_ip + SIZE_ETHERNET + size_icmp;
    icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
 	  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
  }
	//TCP
  if(ip->ip_p == 6)
  {
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
 	  size_tcp = TH_OFF(tcp)*4;
 	   payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		 printf("%s : %d > %s : %d, length %d\n",inet_ntoa(ip->ip_src),htons(tcp->th_sport), inet_ntoa(ip->ip_dst),htons(tcp->th_dport),(u_int)(ntohs(ip->ip_len)));
  }
	// UDP
  if(ip->ip_p == 17)
  {
    size_udp = 8;
    udp = (struct sniff_udp*)((u_char*)packet + SIZE_ETHERNET + size_ip);
 	  payload = (u_char *)(packet + SIZE_ETHERNET + size_udp +size_ip);
		printf("%s : %d > %s : %d, length %d\n",inet_ntoa(ip->ip_src),htons(udp->sport), inet_ntoa(ip->ip_dst),htons(udp->dport),(u_int)(ntohs(ip->ip_len)));
  }

	//Tisk Dat
  PrintData(payload, (u_int)(ntohs(ip->ip_len)));
}



int main (int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  bpf_u_int32 ip;
  bpf_u_int32 mask;
  struct bpf_program fp;
  std::string filter = "";

	// Pipeline pro sniffing - https://www.tcpdump.org/pcap.html
  argument_parse(argc, argv);
  lookupdev(interface,interface_ok);

	// Nastavování zařízení pro sniffing
  int pcaplookupneterr = pcap_lookupnet(interface.c_str(), &ip, &mask,errbuf);
  if(pcaplookupneterr == -1)
  {
    fprintf(stderr, "Wrong interface\n");
    exit(1);
  }

	// Otevírání zařízení
  handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
  if(handle == nullptr)
  {
    fprintf(stderr,"Could not open interface\n");
    exit(1);
  }
	//vytvoření filtru
  filter = make_filter(filter);

  int pcapcompileerr = pcap_compile(handle, &fp, filter.c_str(),0,ip);
  if(pcapcompileerr == -1)
  {
    fprintf(stderr, "Wrong filter\n");
    exit(1);
  }
	// Nastavení filtru
  int pcapsetfiltererr = pcap_setfilter(handle, &fp);
  if(pcapsetfiltererr == -1)
  {
    fprintf(stderr, "Error applying filter\n");
    exit(1);
  }

	//Sniffování Packetů
  int pcaplooperr = pcap_loop(handle, packets_number, callback,NULL);
  if(pcaplooperr == -1)
  {
    fprintf(stderr, pcap_geterr(handle));
    exit(1);
  }
}
