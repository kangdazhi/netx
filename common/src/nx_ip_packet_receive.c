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
/**   Internet Protocol (IP)                                              */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ip.h"
#include "nx_igmp.h"
#include "nx_packet.h"
#include "nx_udp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_packet_receive                               PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function receives a packet from the link driver (usually the   */
/*    link driver's input ISR) and either processes it or places it in a  */
/*    deferred processing queue, depending on the complexity of the       */
/*    packet.                                                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to send     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    (ip_tcp_packet_receive)               Receive a TCP packet          */
/*    (ip_udp_packet_receive)               Receive a UDP packet          */
/*    (ip_icmp_packet_receive)              Receive a ICMP packet         */
/*    (ip_igmp_packet_receive)              Receive a IGMP packet         */
/*    (ip_raw_ip_raw_packet_processing)     Process a Raw IP packet       */
/*    (nx_ip_forward_packet_process)        Forward IP packet             */
/*    _nx_igmp_multicast_check              Check for Multicast match     */
/*    _nx_packet_release                    Packet release function       */
/*    tx_event_flags_set                    Set events for IP thread      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application I/O Driver                                              */
/*    _nx_ip_packet_send                    IP loopback packet send       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  05-19-2020     Yuxin Zhou               Initial Version 6.0           */
/*  09-30-2020     Yuxin Zhou               Modified comment(s),          */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
VOID  _nx_ip_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

TX_INTERRUPT_SAVE_AREA
NX_PACKET     *before_last_packet;
NX_PACKET     *last_packet;
NX_IP_HEADER  *ip_header_ptr;
ULONG         *word_ptr;
ULONG          ip_header_length;
ULONG          protocol;
ULONG          delta;
UCHAR          drop_packet = 0;
NX_UDP_HEADER *udp_header_ptr;
UINT           dest_port;
#ifndef NX_DISABLE_IP_RX_CHECKSUM
ULONG          ip_option_words;
ULONG          checksum;
ULONG          temp;
#endif /* NX_DISABLE_IP_RX_CHECKSUM */


#ifndef NX_DISABLE_IP_INFO

    /* Increment the IP packet count.  */
    ip_ptr -> nx_ip_total_packets_received++;
#endif

    /* If packet_ptr -> nx_packet_ip_interface is not set, stamp the packet with interface[0].
       Legacy Ethernet drivers do not stamp incoming packets. */
    if (packet_ptr -> nx_packet_ip_interface == NX_NULL)
    {
        packet_ptr -> nx_packet_ip_interface = &(ip_ptr -> nx_ip_interface[0]);
    }

    /* It's assumed that the IP link driver has positioned the top pointer in the
       packet to the start of the IP address... so that's where we will start.  */
    ip_header_ptr =  (NX_IP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

#ifdef NX_ENABLE_IP_PACKET_FILTER
    /* Check if the IP packet filter is set.  */
    if (ip_ptr -> nx_ip_packet_filter)
    {

        /* Yes, call the IP packet filter routine.  */
        if ((ip_ptr -> nx_ip_packet_filter((VOID *)(ip_header_ptr), NX_IP_PACKET_IN)) != NX_SUCCESS)
        {

            /* Drop the packet. */
            _nx_packet_release(packet_ptr);
            return;
        }
    }
#endif /* NX_ENABLE_IP_PACKET_FILTER */

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the IP header.  */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_source_ip);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_destination_ip);

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IP_RECEIVE, ip_ptr, ip_header_ptr -> nx_ip_header_source_ip, packet_ptr, packet_ptr -> nx_packet_length, NX_TRACE_INTERNAL_EVENTS, 0, 0)

    /* Make sure the IP length matches the packet length.  Some Ethernet devices
       add padding to small packets, which results in a discrepancy between the
       packet length and the IP header length.  */
    if (packet_ptr -> nx_packet_length != (ip_header_ptr -> nx_ip_header_word_0 & NX_LOWER_16_MASK))
    {

        /* Determine if the packet length is less than the size reported in the IP header.  */
        if (packet_ptr -> nx_packet_length < (ip_header_ptr -> nx_ip_header_word_0 & NX_LOWER_16_MASK))
        {

            /* Packet is too small!  */

#ifndef NX_DISABLE_IP_INFO

            /* Increment the IP invalid packet error.  */
            ip_ptr -> nx_ip_invalid_packets++;

            /* Increment the IP receive packets dropped count.  */
            ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

            /* Invalid packet length, just release it.  */
            _nx_packet_release(packet_ptr);

            /* The function is complete, just return!  */
            return;
        }

        /* Calculate the difference in the length.  */
        delta =  packet_ptr -> nx_packet_length - (ip_header_ptr -> nx_ip_header_word_0 & NX_LOWER_16_MASK);

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - delta;

        /* Adjust the append pointer.  */

        /* Loop to process adjustment that spans multiple packets.  */
        while (delta)
        {

            /* Determine if the packet is chained (or still chained after the adjustment).  */
            if (packet_ptr -> nx_packet_last == NX_NULL)
            {

                /* No, packet is not chained, simply adjust the append pointer in the packet.  */
                packet_ptr -> nx_packet_append_ptr =  packet_ptr -> nx_packet_append_ptr - delta;

                /* Break out of the loop, since the adjustment is complete.  */
                break;
            }

            /* Pickup the pointer to the last packet.  */
            last_packet =  packet_ptr -> nx_packet_last;

            /* Determine if the amount to adjust is less than the payload in the last packet.  */
            if (((ULONG)(last_packet -> nx_packet_append_ptr - last_packet -> nx_packet_prepend_ptr)) > delta)
            {

                /* Yes, simply adjust the append pointer of the last packet in the chain.  */
                last_packet -> nx_packet_append_ptr =  last_packet -> nx_packet_append_ptr - delta;

                /* Get out of the loop, since the adjustment is complete.  */
                break;
            }
            else
            {

                /* Adjust the delta by the amount in the last packet.  */
                delta =  delta - ((ULONG)(last_packet -> nx_packet_append_ptr - last_packet -> nx_packet_prepend_ptr));

                /* Find the packet before the last packet.  */
                before_last_packet =  packet_ptr;
                while (before_last_packet -> nx_packet_next != last_packet)
                {

                    /* Move to the next packet in the chain.  */
                    before_last_packet =  before_last_packet -> nx_packet_next;
                }

                /* At this point, we need to release the last packet and adjust the other packet
                   pointers.  */

                /* Ensure the next packet pointer is NULL in what is now the last packet.  */
                before_last_packet -> nx_packet_next =  NX_NULL;

                /* Determine if the packet is still chained.  */
                if (packet_ptr != before_last_packet)
                {

                    /* Yes, the packet is still chained, setup the last packet pointer.  */
                    packet_ptr -> nx_packet_last =  before_last_packet;
                }
                else
                {

                    /* The packet is no longer chained, set the last packet pointer to NULL.  */
                    packet_ptr -> nx_packet_last =  NX_NULL;
                }

                /* Release the last packet.   */
                _nx_packet_release(last_packet);
            }
        }
    }

    /* Get IP header length. */
    ip_header_length =  (ip_header_ptr -> nx_ip_header_word_0 & NX_IP_LENGTH_MASK) >> 24;

    /* Check for minimal packet length. The check is done after the endian swapping
       since the compiler may possibly be able to optimize the lookup of
       "nx_packet_length" and therefore reduce the amount of work performing these
       size checks. The endian logic is okay since packets must always have
       payloads greater than the IP header in size.  */
    if ((packet_ptr -> nx_packet_length <= (ip_header_length << 2)) ||
        (ip_header_length < NX_IP_NORMAL_LENGTH))
    {

        /* Packet is too small!  */

#ifndef NX_DISABLE_IP_INFO

        /* Increment the IP invalid packet error.  */
        ip_ptr -> nx_ip_invalid_packets++;

        /* Increment the IP receive packets dropped count.  */
        ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

        /* Invalid packet length, just release it.  */
        _nx_packet_release(packet_ptr);

        /* The function is complete, just return!  */
        return;
    }

#ifndef NX_DISABLE_RX_SIZE_CHECKING
#endif /* NX_DISABLE_RX_SIZE_CHECKING */

#ifndef NX_DISABLE_IP_RX_CHECKSUM

    /* Perform a checksum on the packet header.  */
    temp =       ip_header_ptr -> nx_ip_header_word_0;
    checksum =   (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
    temp =       ip_header_ptr -> nx_ip_header_word_1;
    checksum +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
    temp =       ip_header_ptr -> nx_ip_header_word_2;
    checksum +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
    temp =       ip_header_ptr -> nx_ip_header_source_ip;
    checksum +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
    temp =       ip_header_ptr -> nx_ip_header_destination_ip;
    checksum +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);

    /* Add in the carry bits into the checksum.  */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

    /* Do it again in case previous operation generates an overflow.  */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

    /* Take the one's complement.  */
    checksum =   NX_LOWER_16_MASK & ~checksum;

    /* Determine if the checksum is valid.  */
    if (checksum)
    {

        /* Check for IP options before we give up on the packet.  */
        /* Setup a pointer to the first option word.  */
        word_ptr =   ((ULONG *)((VOID *)ip_header_ptr)) + NX_IP_NORMAL_LENGTH;

        /* Determine if there are options in the IP header that make the length greater
           than the default length.  */
        if (ip_header_length > NX_IP_NORMAL_LENGTH)
        {

            /* IP header with options is present.  */

            /* Un-complement the checksum.  */
            checksum =  ~checksum  & NX_LOWER_16_MASK;

            /* Calculate the number of option words.  */
            ip_option_words =  ip_header_length -  NX_IP_NORMAL_LENGTH;

            /* Loop to adjust the checksum.  */
            do
            {

                /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, this macro
                   will swap the endian of the IP header option word.  */
                NX_CHANGE_ULONG_ENDIAN(*word_ptr);

                /* Add this word to the checksum.  */
                temp =  *word_ptr;
                checksum += (temp >> NX_SHIFT_BY_16);
                checksum += (NX_LOWER_16_MASK & temp);

                /* Move the option word pointer and decrement the number of option words.  */
                word_ptr++;
                ip_option_words--;
            } while (ip_option_words);

            /* Add in the carry bits into the checksum.  */
            checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

            /* Do it again in case previous operation generates an overflow.  */
            checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

            /* Perform the one's complement on the checksum again.  */
            checksum =  NX_LOWER_16_MASK & ~checksum;
        }

        /* Check the checksum again.  */
        if (checksum)
        {

#ifndef NX_DISABLE_IP_INFO

            /* Increment the IP invalid packet error.  */
            ip_ptr -> nx_ip_invalid_packets++;

            /* Increment the IP checksum error.  */
            ip_ptr -> nx_ip_receive_checksum_errors++;

            /* Increment the IP receive packets dropped count.  */
            ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

            /* Checksum error, just release it.  */
            _nx_packet_release(packet_ptr);

            /* The function is complete, just return!  */
            return;
        }
        else
        {

            /* If the packet checksum is okay, make sure the source and destination IP
               addresses are placed immediately before the next protocol layer.  */

            /* Build a pointer to what will be the last word of the IP header after we
               remove the IP options.  Basically, all we have to do is move it backwards
               since it was setup previously.  */
            word_ptr--;

            /* Move the destination IP.  */
            *word_ptr-- =  ip_header_ptr -> nx_ip_header_destination_ip;
            *word_ptr-- =  ip_header_ptr -> nx_ip_header_source_ip;
            *word_ptr-- =  ip_header_ptr -> nx_ip_header_word_2;
            *word_ptr-- =  ip_header_ptr -> nx_ip_header_word_1;
            *word_ptr =    (ip_header_ptr -> nx_ip_header_word_0 & ~NX_IP_LENGTH_MASK) |
                NX_IP_VERSION;

            /* Update the ip_header_ptr and the packet and the packet prepend pointer
               and length.  */
            ip_header_ptr =  (NX_IP_HEADER *)((VOID *)word_ptr);
            packet_ptr -> nx_packet_prepend_ptr =  (UCHAR *)word_ptr;
            packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length -
                ((ip_header_length -  NX_IP_NORMAL_LENGTH) * sizeof(ULONG));
        }
    }
#else

    /* IP receive checksum processing is disabled... just check for and remove if
       necessary the IP option words.  */

    /* Check for IP options before we process the packet.  */

    /* Determine if there are options in the IP header that make the length greater
       than the default length.  */
    if (ip_header_length > NX_IP_NORMAL_LENGTH)
    {

        /* Setup a pointer to the last option word.  */
        word_ptr =   ((ULONG *)ip_header_ptr) + ip_header_length - 1;

        /* Remove the option words prior to handling the IP header.  */
        *word_ptr-- =  ip_header_ptr -> nx_ip_header_destination_ip;
        *word_ptr-- =  ip_header_ptr -> nx_ip_header_source_ip;
        *word_ptr-- =  ip_header_ptr -> nx_ip_header_word_2;
        *word_ptr-- =  ip_header_ptr -> nx_ip_header_word_1;
        *word_ptr =    (ip_header_ptr -> nx_ip_header_word_0 & ~NX_IP_LENGTH_MASK) |
            NX_IP_VERSION;

        /* Update the ip_header_ptr and the packet and the packet prepend pointer
           and length.  */
        ip_header_ptr =  (NX_IP_HEADER *)word_ptr;
        packet_ptr -> nx_packet_prepend_ptr =  (UCHAR *)word_ptr;
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length -
            ((ip_header_length -  NX_IP_NORMAL_LENGTH) * sizeof(ULONG));
    }
#endif

#ifdef NX_ENABLE_SOURCE_ADDRESS_CHECK
    /* Check whether source address is valid. */
    /* Section 3.2.1.3, page 30, RFC 1122. */
    if (packet_ptr -> nx_packet_ip_interface -> nx_interface_address_mapping_needed == NX_TRUE)
    {
        if (((ip_header_ptr -> nx_ip_header_source_ip & ~(packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network_mask)) == ~(packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network_mask)) ||
            (((ip_header_ptr -> nx_ip_header_source_ip & ~(packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network_mask)) == 0) &&
             (ip_header_ptr -> nx_ip_header_source_ip != 0)) ||
            ((ip_header_ptr -> nx_ip_header_source_ip & NX_IP_CLASS_D_MASK) == NX_IP_CLASS_D_TYPE))
        {

#ifndef NX_DISABLE_IP_INFO

            /* Increment the IP invalid address error.  */
            ip_ptr -> nx_ip_invalid_receive_address++;

            /* Increment the IP receive packets dropped count.  */
            ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

            /* Toss the IP packet since we don't know what to do with it!  */
            _nx_packet_release(packet_ptr);

            /* Return to caller.  */
            return;
        }
    }
#endif /* NX_ENABLE_SOURCE_ADDRESS_CHECK */

    /* Determine if the IP datagram is for this IP address or a broadcast IP on this
       network.  */
    if ((ip_header_ptr -> nx_ip_header_destination_ip == packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_address) ||

        /* Check for incoming IP address of zero.  Incoming IP address of zero should
           be received regardless of our current IP address.  */
        (ip_header_ptr -> nx_ip_header_destination_ip == 0) ||

        /* Check for IP broadcast.  */
        (((ip_header_ptr -> nx_ip_header_destination_ip & packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network_mask) ==
          packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network) &&
         ((ip_header_ptr -> nx_ip_header_destination_ip & ~(packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network_mask)) ==
          ~(packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network_mask))) ||

        /* Check for limited broadcast.  */
        (ip_header_ptr -> nx_ip_header_destination_ip == NX_IP_LIMITED_BROADCAST) ||

        /* Check for loopback address.  */
        ((ip_header_ptr -> nx_ip_header_destination_ip >= NX_IP_LOOPBACK_FIRST) &&
         (ip_header_ptr -> nx_ip_header_destination_ip <= NX_IP_LOOPBACK_LAST)) ||

        /* Check for valid Multicast address.  */
        (_nx_igmp_multicast_check(ip_ptr, ip_header_ptr -> nx_ip_header_destination_ip, packet_ptr -> nx_packet_ip_interface)))
    {

        /* Determine if this packet is fragmented.  If so, place it on the deferred processing
           queue.  The input packet will then be processed by an IP system thread.  */
        if (ip_header_ptr -> nx_ip_header_word_1 & NX_IP_FRAGMENT_MASK)
        {

#ifndef NX_DISABLE_IP_INFO

            /* Increment the IP receive fragments count.  */
            ip_ptr -> nx_ip_total_fragments_received++;
#endif

            /* Yes, the incoming IP header is fragmented.  Check to see if IP fragmenting
               has been enabled.  */
            if (ip_ptr -> nx_ip_fragment_assembly)
            {

                /* Yes, fragmenting is available.  Place the packet on the incoming
                   fragment queue.  */

                /* Disable interrupts.  */
                TX_DISABLE

                /* Determine if the queue is empty.  */
                if (ip_ptr -> nx_ip_received_fragment_head)
                {

                    /* Raw receive queue is not empty, add this packet to the end of
                       the queue.  */
                    (ip_ptr -> nx_ip_received_fragment_tail) -> nx_packet_queue_next =  packet_ptr;
                    packet_ptr -> nx_packet_queue_next =  NX_NULL;
                    ip_ptr -> nx_ip_received_fragment_tail =  packet_ptr;
                }
                else
                {

                    /* Raw receive queue is empty.  Just setup the head and tail pointers
                       to point to this packet.  */
                    ip_ptr -> nx_ip_received_fragment_head =  packet_ptr;
                    ip_ptr -> nx_ip_received_fragment_tail =  packet_ptr;
                    packet_ptr -> nx_packet_queue_next =      NX_NULL;
                }

                /* Restore interrupts.  */
                TX_RESTORE

                /* Wakeup IP helper thread to process the IP fragment re-assembly.  */
                tx_event_flags_set(&(ip_ptr -> nx_ip_events), NX_IP_UNFRAG_EVENT, TX_OR);
            }
            else
            {

#ifndef NX_DISABLE_IP_INFO

                /* Increment the IP receive packets dropped count.  */
                ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

                /* Fragmentation has not been enabled, toss the packet!  */
                _nx_packet_release(packet_ptr);
            }

            /* In all cases, receive processing is finished.  Return to caller.  */
            return;
        }

        /* Determine what protocol the current IP datagram is.  */
        protocol =  ip_header_ptr -> nx_ip_header_word_2 & NX_IP_PROTOCOL_MASK;

        /* Remove the IP header from the packet.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_IP_HEADER);

        /* Adjust the length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - sizeof(NX_IP_HEADER);

#ifndef NX_DISABLE_IP_INFO

        /* Increment the number of packets delivered.  */
        ip_ptr -> nx_ip_total_packets_delivered++;

        /* Increment the IP packet bytes received (not including the header).  */
        ip_ptr -> nx_ip_total_bytes_received +=  packet_ptr -> nx_packet_length;
#endif

        /* Dispatch the protocol...  Have we found a UDP packet?  */
        if (protocol == NX_IP_UDP)
        {

            if (ip_ptr -> nx_ip_udp_packet_receive)
            {

                /* Yes, dispatch it to the appropriate UDP handler if present.  */
                (ip_ptr -> nx_ip_udp_packet_receive)(ip_ptr, packet_ptr);

                return;
            }

            /* UDP is not enabled. */
            drop_packet = 1;
        }
        /* Is a TCP packet present?  */
        else if (protocol == NX_IP_TCP)
        {
            if (ip_ptr -> nx_ip_tcp_packet_receive)
            {

                /* Yes, dispatch it to the appropriate TCP handler if present.  */
                (ip_ptr -> nx_ip_tcp_packet_receive)(ip_ptr, packet_ptr);

                return;
            }

            /* TCP is not enabled. */
            drop_packet = 1;
        }
        /* Is a ICMP packet present?  */
        else if (protocol == NX_IP_ICMP)
        {
            if (ip_ptr -> nx_ip_icmp_packet_receive)
            {

                /* Yes, dispatch it to the appropriate ICMP handler if present.  */
                (ip_ptr -> nx_ip_icmp_packet_receive)(ip_ptr, packet_ptr);

                return;
            }

            /* ICMP is not enabled. */
            drop_packet = 1;
        }
        else if (protocol == NX_IP_IGMP)
        {
            if (ip_ptr -> nx_ip_igmp_packet_receive)
            {

                /* Yes, dispatch it to the appropriate IGMP handler if present.  */
                (ip_ptr -> nx_ip_igmp_packet_receive)(ip_ptr, packet_ptr);

                return;
            }

            /* IGMP is not enabled. */
            drop_packet = 1;
        }
        /* No protocol found so far.  Determine if RAW IP is supported.  */
        if (ip_ptr -> nx_ip_raw_ip_processing && (drop_packet == 0))
        {

            /* Yes it is. Call the raw IP packet processing routine.  */
            (ip_ptr -> nx_ip_raw_ip_processing)(ip_ptr, packet_ptr);

            /* Done, return to caller.  */
            return;
        }
        else
        {

#ifndef NX_DISABLE_IP_INFO

            /* Decrement the number of packets delivered.  */
            ip_ptr -> nx_ip_total_packets_delivered--;

            /* Decrement the IP packet bytes received (not including the header).  */
            ip_ptr -> nx_ip_total_bytes_received -=  packet_ptr -> nx_packet_length;

            /* Increment the IP unknown protocol count.  */
            ip_ptr -> nx_ip_unknown_protocols_received++;

            /* Increment the IP receive packets dropped count.  */
            ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

            /* Toss the IP packet since we don't know what to do with it!  */
            _nx_packet_release(packet_ptr);

            /* Return to caller.  */
            return;
        }
    }
    /* Does this IP interface define another forward packet handler other
       than the NAT packet handler? */
    else if (ip_ptr -> nx_ip_forward_packet_process)
    {

#ifndef NX_DISABLE_IP_INFO

        /* Increment the IP packets forwarded counter.  */
        ip_ptr -> nx_ip_packets_forwarded++;
#endif

        /* The packet is not for this IP instance so call the
           forward IP packet processing routine.  */
        (ip_ptr -> nx_ip_forward_packet_process)(ip_ptr, packet_ptr);
    }
    /* Try to receive the DHCP message before release this packet.
       NetX should recieve the unicast DHCP message when interface IP address is zero.  */

    /* Check if this IP interface has IP address.  */
    else if (packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_address == 0)
    {

        /* Determine what protocol the current IP datagram is.  */
        protocol =  ip_header_ptr -> nx_ip_header_word_2 & NX_IP_PROTOCOL_MASK;

        /* Check if this packet is UDP message.  */
        if (protocol == NX_IP_UDP)
        {

            /* Remove the IP header from the packet.  */
            packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_IP_HEADER);

            /* Adjust the length.  */
            packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - sizeof(NX_IP_HEADER);

#ifndef NX_DISABLE_IP_INFO

            /* Increment the number of packets delivered.  */
            ip_ptr -> nx_ip_total_packets_delivered++;

            /* Increment the IP packet bytes received (not including the header).  */
            ip_ptr -> nx_ip_total_bytes_received +=  packet_ptr -> nx_packet_length;
#endif

            /* Pickup the pointer to the head of the UDP packet.  */
            udp_header_ptr =  (NX_UDP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

            /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
               swap the endian of the UDP header.  */
            NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);

            /* Pickup the destination UDP port.  */
            dest_port =  (UINT)(udp_header_ptr -> nx_udp_header_word_0 & NX_LOWER_16_MASK);

            /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
               swap the endian of the UDP header.  */
            NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);

            /* Check if this packet is DHCP message.  */
            if (dest_port == 68)
            {
                if (ip_ptr -> nx_ip_udp_packet_receive)
                {

                    /* Yes, dispatch it to the appropriate UDP handler if present.  */
                    (ip_ptr -> nx_ip_udp_packet_receive)(ip_ptr, packet_ptr);

                    return;
                }
            }
        }

#ifndef NX_DISABLE_IP_INFO

        /* Decrement the number of packets delivered.  */
        ip_ptr -> nx_ip_total_packets_delivered--;

        /* Decrement the IP packet bytes received (not including the header).  */
        ip_ptr -> nx_ip_total_bytes_received -=  packet_ptr -> nx_packet_length;

        /* Increment the IP invalid address error.  */
        ip_ptr -> nx_ip_invalid_receive_address++;

        /* Increment the IP receive packets dropped count.  */
        ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

        /* Toss the IP packet since we don't know what to do with it!  */
        _nx_packet_release(packet_ptr);

        /* Return to caller.  */
        return;
    }
    else
    {

#ifndef NX_DISABLE_IP_INFO

        /* Increment the IP invalid address error.  */
        ip_ptr -> nx_ip_invalid_receive_address++;

        /* Increment the IP receive packets dropped count.  */
        ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

        /* Toss the IP packet since we don't know what to do with it!  */
        _nx_packet_release(packet_ptr);

        /* Return to caller.  */
        return;
    }
}

