/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** NetX Component                                                        */
/**                                                                       */
/**   User Specific                                                       */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/*  PORT SPECIFIC C INFORMATION                            RELEASE        */
/*                                                                        */
/*    nx_user.h                                           PORTABLE C      */
/*                                                           6.1.12       */
/*                                                                        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file contains user defines for configuring NetX in specific    */
/*    ways. This file will have an effect only if the application and     */
/*    NetX library are built with NX_INCLUDE_USER_DEFINE_FILE defined.    */
/*    Note that all the defines in this file may also be made on the      */
/*    command line when building NetX library and application objects.    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  05-19-2020     Yuxin Zhou               Initial Version 6.0           */
/*  09-30-2020     Yuxin Zhou               Modified comment(s),          */
/*                                            resulting in version 6.1    */
/*  04-25-2022     Yuxin Zhou               Modified comment(s),          */
/*                                            resulting in version 6.1.11 */
/*  07-29-2022     Yuxin Zhou               Modified comment(s), and      */
/*                                            added NX_ASSERT,            */
/*                                            resulting in version 6.1.12 */
/*                                                                        */
/**************************************************************************/

#ifndef NX_USER_H
#define NX_USER_H


/* Define various build options for the NetX port.  The application should either make changes
   here by commenting or un-commenting the conditional compilation defined OR supply the defines
   though the compiler's equivalent of the -D option.  */


/* Override various options with default values already assigned in nx_api.h or nx_port.h. Please
   also refer to nx_port.h for descriptions on each of these options.  */

/* Defined, this option bypasses the basic NetX error checking. This define is typically used
   after the application is fully debugged.  */

/*
#define NX_DISABLE_ERROR_CHECKING
*/

/* Defined, this option enables IP static routing feature.  By default IP static routing
   feature is not compiled in. */
/*
#define NX_ENABLE_IP_STATIC_ROUTING
*/

/* This define specifies the size of the physical packet header. The default value is 16 (based on
   a typical 16-byte Ethernet header).  */

/*
#define NX_PHYSICAL_HEADER          16
*/


/* This define specifies the size of the physical packet trailer and is typically used to reserve storage
   for things like Ethernet CRCs, etc.  */

/*
#define NX_PHYSICAL_TRAILER         4
*/

/* This defines specifies the number of ThreadX timer ticks in one second. The default value is based
   on ThreadX timer interrupt.  */
/*
#ifdef TX_TIMER_TICKS_PER_SECOND
#define NX_IP_PERIODIC_RATE         TX_TIMER_TICKS_PER_SECOND
#else
#define NX_IP_PERIODIC_RATE         100
#endif
*/

/* When defines, ARP reply is sent when address conflict occurs. */
/*
#define NX_ARP_DEFEND_BY_REPLY
*/

/* To use the ARP collision handler to check for invalid ARP messages
   matching existing entries in the table (man in the middle attack),
   enable this feature.  */
/*
#define  NX_ENABLE_ARP_MAC_CHANGE_NOTIFICATION
*/

/* This define specifies the number of seconds ARP entries remain valid. The default value of 0 disables
   aging of ARP entries.  */

/*
#define NX_ARP_EXPIRATION_RATE      0
*/


/* This define specifies the number of seconds between ARP retries. The default value is 10, which represents
   10 seconds.  */

/*
#define NX_ARP_UPDATE_RATE          10
*/


/* This define specifies how the number of system ticks (NX_IP_PERIODIC_RATE) is divided to calculate the
   timer rate for the TCP delayed ACK processing. The default value is 5, which represents 200ms.  */

/*
#define NX_TCP_ACK_TIMER_RATE       5
*/


/* This define specifies how the number of system ticks (NX_IP_PERIODIC_RATE) is divided to calculate the
   fast TCP timer rate. The fast TCP timer is used to drive various TCP timers, including the delayed ACK
   timer. The default value is 10, which represents 100ms.  */

/*
#define NX_TCP_FAST_TIMER_RATE      10
*/


/* This define specifies how the number of system ticks (NX_IP_PERIODIC_RATE) is divided to calculate the
   timer rate for the TCP transmit retry processing. The default value is 1, which represents 1 second.  */

/*
#define NX_TCP_TRANSMIT_TIMER_RATE  1
*/


/* This define specifies how many seconds of inactivity before the keepalive timer activates. The default
   value is 7200, which represents 2 hours.   */

/*
#define NX_TCP_KEEPALIVE_INITIAL    7200
*/


/* This define specifies how many seconds between retries of the keepalive timer assuming the other side
   of the connection is not responding. The default value is 75, which represents 75 seconds between
   retries.  */

/*
#define NX_TCP_KEEPALIVE_RETRY      75
*/


/* This define specifies the maximum number of ARP retries made without an ARP response. The default
   value is 18.  */

/*
#define NX_ARP_MAXIMUM_RETRIES      18
*/


/* This defines specifies the maximum number of packets that can be queued while waiting for an ARP
   response. The default value is 4.  */

/*
#define NX_ARP_MAX_QUEUE_DEPTH      4
*/


/* Defined, this option disables entering ARP request information in the ARP cache.  */

/*
#define NX_DISABLE_ARP_AUTO_ENTRY
*/


/* This define specifies the maximum number of multicast groups that can be joined. The default value is
   7.  */

/*
#define NX_MAX_MULTICAST_GROUPS     7
*/


/* This define specifies the maximum number of TCP server listen requests. The default value is 10.  */

/*
#define NX_MAX_LISTEN_REQUESTS      10
*/


/* Defined, this option enables the optional TCP keepalive timer.  */

/*
#define NX_ENABLE_TCP_KEEPALIVE
*/


/* Defined, this option enables the TCP window scaling feature. (RFC 1323). Default disabled. */
/*
#define NX_ENABLE_TCP_WINDOW_SCALING
*/



/* Defined, this option enables the optional TCP immediate ACK response processing.  */

/*
#define NX_TCP_IMMEDIATE_ACK
*/

/* This define specifies the number of TCP packets to receive before sending an ACK. */
/* The default value is 2: ack every 2 packets.                                      */
/*
#define NX_TCP_ACK_EVERY_N_PACKETS  2
*/

/* Automatically define NX_TCP_ACK_EVERY_N_PACKETS to 1 if NX_TCP_IMMEDIATE_ACK is defined.
   This is needed for backward compatibility. */
#if (defined(NX_TCP_IMMEDIATE_ACK) && !defined(NX_TCP_ACK_EVERY_N_PACKETS))
#define NX_TCP_ACK_EVERY_N_PACKETS 1
#endif


/* This define specifies how many transmit retires are allowed before the connection is deemed broken.
   The default value is 10.  */

/*
#define NX_TCP_MAXIMUM_RETRIES      10
*/


/* This define specifies the maximum depth of the TCP transmit queue before TCP send requests are
   suspended or rejected. The default value is 20, which means that a maximum of 20 packets can be in
   the transmit queue at any given time.  */

/*
#define NX_TCP_MAXIMUM_TX_QUEUE     20
*/


/* This define specifies how the retransmit timeout period changes between successive retries. If this
   value is 0, the initial retransmit timeout is the same as subsequent retransmit timeouts. If this
   value is 1, each successive retransmit is twice as long. The default value is 0.  */

/*
#define NX_TCP_RETRY_SHIFT          0
*/


/* This define specifies how many keepalive retries are allowed before the connection is deemed broken.
   The default value is 10.  */

/*
#define NX_TCP_KEEPALIVE_RETRIES    10
*/


/* Defined, this option enables deferred driver packet handling. This allows the driver to place a raw
   packet on the IP instance and have the driver's real processing routine called from the NetX internal
   IP helper thread.  */

/*
#define NX_DRIVER_DEFERRED_PROCESSING
*/


/* Defined, this option disables NetX support on the 127.0.0.1 loopback interface.
   127.0.0.1 loopback interface is enabled by default.  Uncomment out the follow code to disable
   the loopback interface. */
/*
#define NX_DISABLE_LOOPBACK_INTERFACE
*/

/* This option defines the number of physical network interfaces to support.  Default is one*/
/*
#define NX_MAX_PHYSICAL_INTERFACES 1
*/

/* Defined, this option disables all IP fragmentation logic.  */

/*
#define NX_DISABLE_FRAGMENTATION
*/


/* Defined, this option disables checksum logic on received IP packets. This is useful if the link-layer
   has reliable checksum or CRC logic.  */

/*
#define NX_DISABLE_IP_RX_CHECKSUM
*/


/* Defined, this option disables checksum logic on transmitted IP packets.  */

/*
#define NX_DISABLE_IP_TX_CHECKSUM
*/


/* Defined, this option disables checksum logic on received TCP packets.  */

/*
#define NX_DISABLE_TCP_RX_CHECKSUM
*/


/* Defined, this option disables checksum logic on transmitted TCP packets.  */

/*
#define NX_DISABLE_TCP_TX_CHECKSUM
*/

/* Defined, this option disables checksum logic on received UDP packets.  */

/*
#define NX_DISABLE_UDP_RX_CHECKSUM
*/


/* Defined, this option disables checksum logic on transmitted UDP packets.  */

/*
#define NX_DISABLE_UDP_TX_CHECKSUM
*/


/* Defined, this option disables checksum logic on received ICMP packets.  */
/*
#define NX_DISABLE_ICMP_RX_CHECKSUM
*/


/* Defined, this option disables checksum logic on transmitted ICMP packets.  */
/*
#define NX_DISABLE_ICMP_TX_CHECKSUM
*/


/* Defined, this option disables the reset processing during disconnect when the timeout value is
   specified as NX_NO_WAIT.  */

/*
#define NX_DISABLE_RESET_DISCONNECT
*/

/* Defined, this option disables the addition size checking on received packets.  */

/*
#define NX_DISABLE_RX_SIZE_CHECKING
*/


/* Defined, ARP information gathering is disabled.  */

/*
#define NX_DISABLE_ARP_INFO
*/


/* Defined, IP information gathering is disabled.  */

/*
#define NX_DISABLE_IP_INFO
*/


/* Defined, ICMP information gathering is disabled.  */

/*
#define NX_DISABLE_ICMP_INFO
*/

/* Defined, IGMP v2 support is disabled.  By default NetX
   is built with IGMPv2 enabled .  By uncommenting this option,
   NetX reverts back to IGMPv1 only. */
/*
#define NX_DISABLE_IGMPV2
*/

/* Defined, IGMP information gathering is disabled.  */

/*
#define NX_DISABLE_IGMP_INFO
*/


/* Defined, packet information gathering is disabled.  */

/*
#define NX_DISABLE_PACKET_INFO
*/


/* Defined, RARP information gathering is disabled.  */

/*
#define NX_DISABLE_RARP_INFO
*/


/* Defined, TCP information gathering is disabled.  */

/*
#define NX_DISABLE_TCP_INFO
*/


/* Defined, UDP information gathering is disabled.  */

/*
#define NX_DISABLE_UDP_INFO
*/


/* Defined, extended notify support is enabled.  This feature adds additional callback/notify services
   to NetX API for notifying the host of socket events, such as TCP connection and disconnect
   completion.  The default is that the extended notify feature is enabled.   */
/*
#define NX_ENABLE_EXTENDED_NOTIFY_SUPPORT
*/


/* Defined, NX_PACKET structure is padded for alignment purpose. The default is no padding. */
/*
#define NX_PACKET_HEADER_PAD
#define NX_PACKET_HEADER_PAD_SIZE 1
*/

/* If defined, the incoming SYN packet (connection request) is checked for a minimum acceptable
   MSS for the host to accept the connection. The default minimum should be based on the host
   application packet pool payload, socket transmit queue depth and relevant application specific parameters.
#define NX_ENABLE_TCP_MSS_CHECKING
#define NX_TCP_MSS_MINIMUM              128
*/

/* Defined, the source address of incoming packet is checked. The default is disabled. */
/*
#define NX_ENABLE_SOURCE_ADDRESS_CHECK
*/

/* Define the ARP defend interval. The default value is 10 seconds.  */
/*
#define NX_ARP_DEFEND_INTERVAL  10
*/

/* To limit the number of out of order packets stored to the TCP receive queue and prevent
   possible packet pool depletion, define this to a non zero value:

#define NX_TCP_MAX_OUT_OF_ORDER_PACKETS 8
*/

/* Defined, the destination address of ICMP packet is checked. The default is disabled.
   An ICMP Echo Request destined to an IP broadcast or IP multicast address will be silently discarded.
*/
/*
#define NX_ENABLE_ICMP_ADDRESS_CHECK
*/

/* Define the max string length. The default value is 1024.  */
/*
#define NX_MAX_STRING_LENGTH                                1024
*/

/* Defined, ASSERT is disabled. The default is enabled. */
/*
#define NX_DISABLE_ASSERT
*/

/* Define the process when assert fails. */
/*
#define NX_ASSERT_FAIL while (1) tx_thread_sleep(NX_WAIT_FOREVER);
*/

#endif

