/*
* Name		: dhcp-stats.c
* Project	: Monitorovani DHCP komunikace (Matej Gregr)
* Author	: Jozef Bilko (xbilko03)
*/

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <ncurses.h>
#include <pcap.h>
#include <math.h>
#include "btree.h"

void PrintError(char* message);
void AnalyzeFileAndPrint(char* fileName, struct ip_range rangeList[maxPrefixes], u_int32_t suffixCount, struct node* root);
void AnalyzeInterfaceAndPrint(char* interfaceName, struct ip_range rangeList[maxPrefixes], u_int32_t suffixCount, struct node* root);
void PrintToStd(struct ip_range rangeList[maxPrefixes], u_int32_t prefixCount);
bool IsWithinRange(u_int32_t ip, char* base, char* prefix);
void PrintToWindow(struct ip_range rangeList[maxPrefixes], u_int32_t prefixCount);
void PrintHelpAndExit();

#define MIN_SUBNET_MASK 1
#define MAX_SUBNET_MASK 30
#define ETHERNET_HDR_SIZE 14
#define MAGIC_COOKIE 1669485411
#define BYTE_SKIP_TO_COOKIE 236

int main(int argc, char** argv)
{
    /* Parse options */
    int flag = 0;
    int opt;
    char* operationType;
    while ((opt = getopt(argc, argv, "i:r:h")) != -1) {
        switch (opt) {
        case 'i':
            if (flag == 1)
                PrintError("only one option may be used at a time.");
            operationType = "observe";
            flag = 1;
            break;
        case 'r':
            if (flag == 1)
                PrintError("only one option may be used at a time.");
            operationType = "read";
            flag = 1;
            break;
        case 'h':
            PrintHelpAndExit();
            break;
        default:
            PrintError("wrong options usage.");
        }
    }
    if (flag == 0)
        PrintError("need to use atleast one option [-r <filename>] or [-i <interface-name>].\n");
    
    /* Create IPV4 IP ranges list (ip-prefix list) */
    struct ip_range rangeList[maxPrefixes];
    struct node* root = NULL;
    int i = 0;
    int prefixCount = argc - optind;
    while (i < prefixCount)
    {
        rangeList[i].range = argv[optind + i];
        rangeList[i].logged = false;
        i++;
    }

    /* For each ip-prefix calculate their maximum possible hosts */
    i = 0;
    while (i < prefixCount)
    {
        rangeList[i].range = strtok(rangeList[i].range, "/");
        rangeList[i].suffix = strtok(NULL, "/");
        if (rangeList[i].suffix == NULL)
            PrintError("IP-prefix is not valid");
        rangeList[i].maxhosts = pow(2, (32 - atoi(rangeList[i].suffix)));
        if (atoi(rangeList[i].suffix) < MIN_SUBNET_MASK || atoi(rangeList[i].suffix) > MAX_SUBNET_MASK)
            PrintError("IP-prefix is not valid");
        if (rangeList[i].maxhosts > 2)
            rangeList[i].maxhosts -= 2;

        rangeList[i].allocated = 0;
        i++;
    }

    /* Reads from pcap file */
    if (strcmp(operationType, "read") == 0)
        AnalyzeFileAndPrint(argv[2], rangeList, prefixCount, root);
    /* Monitor the interface */
    else
        AnalyzeInterfaceAndPrint(argv[2], rangeList, prefixCount, root);

    return 0;
}
void AnalyzeFileAndPrint(char* fileName, struct ip_range rangeList[maxPrefixes], u_int32_t prefixCount, struct node* root)
{
    /* Syslog setup */
    setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog("dhcpcomm", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    float percent;

    /* Error string */
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Initialize the library for local character encoding (if needed) */
    /* pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf); */

    /* Open pcap file */
    pcap_t* targetFile = pcap_open_offline(fileName, errbuf);
    if (targetFile == NULL)
        PrintError("Could not open a file");

    /* Packet & file handlers 
    * inspired by https://www.tcpdump.org/pcap.html
    * Tim Carstens and Guy Harris
    */
    struct pcap_pkthdr* header;
    const unsigned char* packet;
    int x, y, dhcpStart, optionsPosition;
    int i;
    u_int32_t sourcePort, cookie;
    uint32_t yiaddr;

    /* Read packets until there are none left in the file */
    while(pcap_next_ex(targetFile, &header, &packet) == 1)
    {
        /* 
        * Skip 36bytes
        * ETHERNET_HDR_SIZE (14)
        * 20 udp header
        * 2 live capture offset
        * -1 to adjust for index position
        */

        /* Number of bytes to skip (IPV4 header) */
        x = (*(uint8_t*)(packet + ETHERNET_HDR_SIZE) & 0x0F) * 4;

        /* IPV4 version in the upper 4 bits, skip packet if it does not fit */
        y = *(uint8_t*)(packet + ETHERNET_HDR_SIZE) >> 4;
        if (y != 4)
            continue;
        sourcePort = htons(*(uint16_t*)(packet + x + ETHERNET_HDR_SIZE));

        /* IPV4 version in the upper 4 bits, skip packet if it does not fit */
        if (sourcePort != 67)
            continue;
        dhcpStart = x + 22;

        /* Yiaddr, address given, acknowledged by the server */
        yiaddr = htonl(*(uint32_t*)(packet + dhcpStart + 16));

        /* Check for magic cookie */
        cookie = htonl(*(uint32_t*)(packet + dhcpStart + BYTE_SKIP_TO_COOKIE));
        if (cookie != MAGIC_COOKIE)
            continue;
        
        /* Skip magic cookie */
        optionsPosition = dhcpStart + BYTE_SKIP_TO_COOKIE + 4;

        /* Skip magic cookie, check whether there are options */
        while (optionsPosition < header->len)
        {
            /* Check for acknowledged (ACK) option */
            if (*(uint8_t*)(packet + optionsPosition) == 53 && *(uint8_t*)(packet + optionsPosition + 2) == 5)
            {
                /* If server already acknowledged the address, we throw the packet away */
                if (TreeContains(root, yiaddr) == false)
                {
                    root = TreeInsert(root, yiaddr);
                    for (i = 0; i < prefixCount; i++)
                    {
                        /* For each prefix, check if it within range */
                        if (IsWithinRange(yiaddr, rangeList[i].range, rangeList[i].suffix) == true)
                        {
                            rangeList[i].allocated++;

                            /* If above 50% for this prefix, print to syslog */
                            if (rangeList[i].logged == false)
                            {
                                percent = roundf((float)rangeList[i].allocated / (float)rangeList[i].maxhosts * 10000) / 100;
                                if (percent >= 50.00f)
                                {
                                    syslog(LOG_NOTICE, "prefix %s/%s exceeded 50%% of allocations", rangeList[i].range, rangeList[i].suffix);
                                    rangeList[i].logged = true;
                                }
                            }
                        }
                    }
                }
                break;
            }
            /* Skip to the next option */
            optionsPosition += *(uint8_t*)(packet + optionsPosition + 1) + 2;
        }
    }
    PrintToStd(rangeList, prefixCount);
    DestroyTree(root);
    pcap_close(targetFile);
    closelog();
    return;
}
void AnalyzeInterfaceAndPrint(char* interfaceName, struct ip_range rangeList[maxPrefixes], u_int32_t prefixCount, struct node* root)
{
    /* Syslog setup */
    setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog("dhcpcomm", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    float percent;

    /* Error string */
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Initialize the library for local character encoding (if needed) */
    /* pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf); */

    /* Packet & interface handlers
    * inspired by https://www.tcpdump.org/pcap.html
    * Tim Carstens and Guy Harris
    */
    const unsigned char* packet;
    int x, i, y, dhcpStart, optionsPosition;
    u_int32_t sourcePort, cookie, yiaddr;
    pcap_t* handle;
    bpf_u_int32 mask, net;
    struct pcap_pkthdr header;

    /* Check whether device is available */
    pcap_if_t* deviceList;
    bool available = false;
    if (pcap_findalldevs(&deviceList, errbuf) == 0)
    {
        while (deviceList)
        {
            if (strcmp(deviceList->name, interfaceName) == 0)
            {
                available = true;
                break;
            }
            deviceList = deviceList->next;
        }
    }
    if (available == false)
        PrintError("The interface is not available");

    /* Find the properties for the device */
    if (pcap_lookupnet(interfaceName, &net, &mask, errbuf) == -1)
    {
        PrintError(errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
        PrintError(errbuf);

    /* Ncurses setup */
    initscr();
    PrintToWindow(rangeList, prefixCount);

    /* Read packets until there are none left in the file */
    while ((packet = pcap_next(handle, &header))) //careful here
    {
        /* Skip 36bytes = ETHERNET_HDR_SIZE (14) + 20 udp header +  2 live capture offset -1 to adjust for index position */

        /* Number of bytes to skip (IPV4 header) */
        x = (*(uint8_t*)(packet + ETHERNET_HDR_SIZE + 2) & 0x0F) * 4;
        
        /* IPV4 version in the upper 4 bits, skip packet if it does not fit */
        y = *(uint8_t*)(packet + ETHERNET_HDR_SIZE + 2) >> 4;
        if (y != 4)
            continue;
        sourcePort = htons(*(uint16_t*)(packet + x + ETHERNET_HDR_SIZE + 2));

        /* IPV4 version in the upper 4 bits, skip packet if it does not fit */
        if (sourcePort != 67)
            continue;
        dhcpStart = x + 22;

        /* Yiaddr, address given, acknowledged by the server */
        yiaddr = htonl(*(uint32_t*)(packet + dhcpStart + 16 + 2));

        /* Check for magic cookie */
        cookie = htonl(*(uint32_t*)(packet + dhcpStart + BYTE_SKIP_TO_COOKIE + 2));
        if (cookie != MAGIC_COOKIE)
            continue;

        /* Skip magic cookie */
        optionsPosition = dhcpStart + BYTE_SKIP_TO_COOKIE + 4 + 2;

        /* Skip magic cookie, check whether there are options */
        while (optionsPosition < header.len)
        {
            /* Check for acknowledged (ACK) option */
            if (*(uint8_t*)(packet + optionsPosition) == 53 && *(uint8_t*)(packet + optionsPosition + 2) == 5)
            {
                /* If server already acknowledged the address, we throw the packet away */
                if (TreeContains(root, yiaddr) == false)
                {
                    root = TreeInsert(root, yiaddr);
                    for (i = 0; i < prefixCount; i++)
                    {
                        /* For each prefix, check if it within range */
                        if (IsWithinRange(yiaddr, rangeList[i].range, rangeList[i].suffix) == true)
                        {
                            rangeList[i].allocated++;

                            /* If above 50% for this prefix, print to syslog */
                            if (rangeList[i].logged == false)
                            {
                                percent = roundf((float)rangeList[i].allocated / (float)rangeList[i].maxhosts * 10000) / 100;
                                if (percent >= 50.00f)
                                {
                                    syslog(LOG_NOTICE, "prefix %s/%s exceeded 50%% of allocations", rangeList[i].range, rangeList[i].suffix);
                                    rangeList[i].logged = true;
                                }
                            }
                        }
                    }
                    PrintToWindow(rangeList, prefixCount);
                }
                break;
            }
            /* Skip to the next option */
            optionsPosition += *(uint8_t*)(packet + optionsPosition + 1) + 2;
        }
    }
    DestroyTree(root);
    closelog();
    endwin();

    exit(EXIT_SUCCESS);
}
void PrintToStd(struct ip_range rangeList[maxPrefixes], u_int32_t prefixCount)
{
    int i = 0;
    float percent;
    fprintf(stdout, "IP-Prefix Max-hosts Allocated addresses Utilization\n");
    /* For each prefix, print its statistics */
    while (i < prefixCount)
    {
        if (rangeList[i].maxhosts > 0)
            percent = roundf((float)rangeList[i].allocated / (float)rangeList[i].maxhosts * 10000) / 100;
        else
            percent = 0;
        fprintf(stdout,"%s/%s %u %u %.2f%%\n", rangeList[i].range, rangeList[i].suffix, rangeList[i].maxhosts, rangeList[i].allocated, percent);
        i++;
    }
}
void PrintToWindow(struct ip_range rangeList[maxPrefixes], u_int32_t prefixCount)
{
    int i = 0;
    float percent;

    printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");
    /* For each prefix, print its statistics */
    while (i < prefixCount)
    {
        if (rangeList[i].maxhosts > 0)
            percent = roundf((float)rangeList[i].allocated / (float)rangeList[i].maxhosts * 10000) / 100;
        else
            percent = 0;
        printw("%s/%s %u %u %.2f%%\n", rangeList[i].range, rangeList[i].suffix, rangeList[i].maxhosts, rangeList[i].allocated, percent);
        i++;
    }
    refresh();
    clear();
}
bool IsWithinRange(u_int32_t ip, char* base,char* suffix)
{
    /* Shift ip-prefix and ip to the right, by the value of subnet */
    u_int32_t newAddr;
    inet_pton(AF_INET, base, &newAddr);
    newAddr = htonl(newAddr);
    u_int32_t newIp = ip;
    int subnet = 32 - atoi(suffix);

    /* ip-prefix */
    newAddr = newAddr >> subnet;
    /* yiaddr */
    newIp = newIp >> subnet;

    /* Exclude 0.0.0.0 and FF.FF.FF.FF */
    u_int32_t reserved = ip << (32 - subnet);
    reserved = reserved >> (32 - subnet);
    if (reserved == (0b11111111111111111111111111111111 >> (32 - subnet)) || reserved == (0b00000000000000000000000000000000 >> (32 - subnet)))
        return false;

    /* If they equal, the ip belongs to this ip-prefix */
    if (newIp == newAddr)
    {
        return true;
    }
    else
        return false;
}
void PrintError(char* message)
{
    fprintf(stderr, "dhcp-stats: %s\n", message);
    exit(EXIT_FAILURE);
}
void PrintHelpAndExit()
{
    fprintf(stdout, "NAME\n\tdhcp - stats - simple DHCP statistics collector\n\n");
    fprintf(stdout, "SYNOPSIS\n\tGather statistics about DHCP communication and print them on screen\n\n");
    fprintf(stdout, "DESCRIPTION\n\tdhcp - stats  is a C / C++ program for monitoring an interface or reading a.pcap file and printing the statistics of the DHCP communication onto the screen.\n\tIn case 50%% of a prefix should be allocated, the information is logged.\n\n");
    fprintf(stdout, "USE-EXAMPLE\n\t.dhcp - stats - i any 192.168.1.0/24 192.168.0.0/22 171.16.32.0/24\n\n");
    fprintf(stdout, "SEE ALSO\n\tNothing else to see at the moment.\n\n");
    fprintf(stdout, "BUGS\n\tPrefix addresses such as abc / 20 are evaluated as valid, the behavior is undefined.\n\n");
    fprintf(stdout, "AUTHOR\n\tJozef Bilko(xbilko03)\n");
    exit(EXIT_SUCCESS);
}