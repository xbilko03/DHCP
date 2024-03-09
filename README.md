# DHCP monitor
## NAME
       dhcp-stats - simple DHCP statistics collector

## SYNOPSIS
       Gather statistics about DHCP communication and print them on screen

## DESCRIPTION
       dhcp-stats  is a C/C++ program for monitoring an interface or reading a .pcap file and printing the statistics
       of the DHCP communication onto the screen. In case 50% of a prefix should be  allocated,  the  information  is
       logged. Input is limited to certain subnets, from 1 up to 30

## OPTIONS
       [-i interface  - interface to monitor] [-r filename - file to read] <ip-prefix> [<ip-prefix>]

## USE-EXAMPLE
       .dhcp-stats -i any 192.168.1.0/24 192.168.0.0/22 171.16.32.0/24

## SEE ALSO
       Nothing else to see at the moment.

## BUGS
       Prefix addresses such as abc/20 are evaluated as valid, the behavior is undefined.

## AUTHOR
       Jozef Bilko (xbilko03)

## LAST-UPDATE
	11/19/2023

## FILES
	manual.pdf, Makefile, dhcp-stats.1, README, dhcp-stats.c, btree.c, btree.h
