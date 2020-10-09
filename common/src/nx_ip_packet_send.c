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
#include "nx_packet.h"
#include "nx_igmp.h"
#include "nx_arp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_packet_send                                  PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function prepends an IP header and sends an IP packet to the   */
/*    appropriate link driver.                                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to send     */
/*    destination_ip                        Destination IP address        */
/*    type_of_service                       Type of service for packet    */
/*    time_to_live                          Time to live value for packet */
/*    protocol                              Protocol being encapsulated   */
/*    fragment                              Don't fragment bit            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_copy                       Copy packet for loopback      */
/*    _nx_packet_transmit_release           Release transmit packet       */
/*    _nx_ip_loopback_send                  Send packet via the LB driver */
/*    (nx_ip_fragment_processing)           Fragment processing           */
/*    (ip_link_driver)                      User supplied link driver     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX Source Code                                                    */
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

VOID  _nx_ip_packet_send(NX_IP *ip_ptr, NX_PACKET *packet_ptr,
                         ULONG destination_ip, ULONG type_of_service, ULONG time_to_live, ULONG protocol, ULONG fragment)
{

TX_INTERRUPT_SAVE_AREA
NX_IP_DRIVER  driver_request;
NX_IP_HEADER *ip_header_ptr;

#ifndef NX_DISABLE_IP_TX_CHECKSUM
ULONG      checksum;
ULONG      temp;
#endif /* !NX_DISABLE_IP_TX_CHECKSUM */
UINT       index;
NX_ARP    *arp_ptr;
NX_PACKET *last_packet;
NX_PACKET *remove_packet;
UINT       queued_count;


#ifndef NX_DISABLE_IP_INFO

    /* Increment the total send requests counter.  */
    ip_ptr -> nx_ip_total_packet_send_requests++;
#endif /* !NX_DISABLE_IP_INFO */

    /* Prepend the IP header to the packet.  First, make room for the IP header.  */
    packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr - sizeof(NX_IP_HEADER);

    /* Increase the packet length.  */
    packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length + sizeof(NX_IP_HEADER);

    /* Make sure the packet interface or next hop (e.g. gateway) is set. */
    if ((packet_ptr -> nx_packet_ip_interface == NX_NULL) || (packet_ptr -> nx_packet_next_hop_address == 0))
    {

#ifndef NX_DISABLE_IP_INFO

        /* Increment the IP invalid packet error.  */
        ip_ptr -> nx_ip_invalid_transmit_packets++;
#endif /* !NX_DISABLE_IP_INFO */

        /* Release the packet. Note that at this point the prepend_ptr points to the beginning of the IP header. */
        _nx_packet_transmit_release(packet_ptr);

        /* Return... nothing more can be done!  */
        return;
    }

    /* If the IP header won't fit, return an error.  */
    if (packet_ptr -> nx_packet_prepend_ptr < packet_ptr -> nx_packet_data_start)
    {

#ifndef NX_DISABLE_IP_INFO

        /* Increment the IP invalid packet error.  */
        ip_ptr -> nx_ip_invalid_transmit_packets++;
#endif  /* !NX_DISABLE_IP_INFO */

        /* Release the packet.  Note that at this point the prepend_ptr points to the beginning of the IP header. */
        _nx_packet_transmit_release(packet_ptr);

        /* Return... nothing more can be done!  */
        return;
    }

    /* Build the IP header.  */

    /* Setup the IP header pointer.  */
    ip_header_ptr =  (NX_IP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /* Build the first 32-bit word of the IP header.  */
    ip_header_ptr -> nx_ip_header_word_0 =  (NX_IP_VERSION | type_of_service | (0xFFFF & packet_ptr -> nx_packet_length));

    /* Build the second 32-bit word of the IP header.  */
    ip_header_ptr -> nx_ip_header_word_1 =  (ip_ptr -> nx_ip_packet_id++ << NX_SHIFT_BY_16) | fragment;

    /* Build the third 32-bit word of the IP header.  */
    ip_header_ptr -> nx_ip_header_word_2 =  ((time_to_live << NX_IP_TIME_TO_LIVE_SHIFT) | protocol);

    /* Place the source IP address in the IP header.  */
    ip_header_ptr -> nx_ip_header_source_ip =  packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_address;

    /* Place the destination IP address in the IP header.  */
    ip_header_ptr -> nx_ip_header_destination_ip =  destination_ip;

#ifndef NX_DISABLE_IP_TX_CHECKSUM

    /* Build the IP header checksum.  */
    temp =       ip_header_ptr -> nx_ip_header_word_0;
    checksum =   (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
    temp =       ip_header_ptr -> nx_ip_header_word_1;
    checksum +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
    temp =       ip_header_ptr -> nx_ip_header_word_2;
    checksum +=  (temp >> NX_SHIFT_BY_16);
    temp =       ip_header_ptr -> nx_ip_header_source_ip;
    checksum +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
    temp =       ip_header_ptr -> nx_ip_header_destination_ip;
    checksum +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);

    /* Add in the carry bits into the checksum.  */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

    /* Do it again in case previous operation generates an overflow.  */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

    /* Now store the checksum in the IP header.  */
    ip_header_ptr -> nx_ip_header_word_2 =  ip_header_ptr -> nx_ip_header_word_2 | (NX_LOWER_16_MASK & (~checksum));
#endif /* !NX_DISABLE_IP_TX_CHECKSUM */

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IP_SEND, ip_ptr, destination_ip, packet_ptr, packet_ptr -> nx_packet_length, NX_TRACE_INTERNAL_EVENTS, 0, 0)

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the IP header.  */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_source_ip);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_destination_ip);

#ifdef NX_ENABLE_IP_PACKET_FILTER
    /* Check if the IP packet filter is set.  */
    if (ip_ptr -> nx_ip_packet_filter)
    {

        /* Yes, call the IP packet filter routine.  */
        if ((ip_ptr -> nx_ip_packet_filter((VOID *)(ip_header_ptr), NX_IP_PACKET_OUT)) != NX_SUCCESS)
        {

            /* Drop the packet. */
            _nx_packet_transmit_release(packet_ptr);
            return;
        }
    }
#endif /* NX_ENABLE_IP_PACKET_FILTER */

    /* Take care of the loopback case. */
    if ((destination_ip == packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_address) ||
        ((destination_ip >= NX_IP_LOOPBACK_FIRST) && (destination_ip <= NX_IP_LOOPBACK_LAST)))
    {
        /* Send the packet via the loopback driver, and release the original
           packet after loopback send. */
        _nx_ip_loopback_send(ip_ptr, packet_ptr, NX_TRUE);

        return;
    }

    /* Determine if physical mapping is needed by the link driver.  */
    if (packet_ptr -> nx_packet_ip_interface -> nx_interface_address_mapping_needed)
    {

        /* Yes, Check for broadcast address. */

        /* Determine if an IP limited or directed broadcast is requested.  */
        if ((destination_ip == NX_IP_LIMITED_BROADCAST) ||
            (((destination_ip & packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network_mask) == packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network) &&
             ((destination_ip & ~(packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network_mask)) == ~(packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_network_mask))))
        {

            /* Build the driver request.  */
            driver_request.nx_ip_driver_ptr                  =  ip_ptr;
            driver_request.nx_ip_driver_command              =  NX_LINK_PACKET_BROADCAST;
            driver_request.nx_ip_driver_packet               =  packet_ptr;
            driver_request.nx_ip_driver_physical_address_msw =  0xFFFFUL;
            driver_request.nx_ip_driver_physical_address_lsw =  0xFFFFFFFFUL;
            driver_request.nx_ip_driver_interface            =  packet_ptr -> nx_packet_ip_interface;
#ifndef NX_DISABLE_FRAGMENTATION
            /* Determine if fragmentation is needed.  */
            if ((packet_ptr -> nx_packet_length) > (packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_mtu_size))
            {

                /* Fragmentation is needed, call the fragment routine if available. */
                if (ip_ptr -> nx_ip_fragment_processing)
                {

                    /* Call the IP fragment processing routine.  */
                    (ip_ptr -> nx_ip_fragment_processing)(&driver_request);
                }
                else
                {

#ifndef NX_DISABLE_IP_INFO

                    /* Increment the IP send packets dropped count.  */
                    ip_ptr -> nx_ip_send_packets_dropped++;
#endif /* !NX_DISABLE_IP_INFO */

                    /* Just release the packet.  */
                    _nx_packet_transmit_release(packet_ptr);
                }

                /* In either case, this packet send is complete, just return.  */
                return;
            }
#endif /* !NX_DISABLE_FRAGMENTATION */

#ifndef NX_DISABLE_IP_INFO

            /* Increment the IP packet sent count.  */
            ip_ptr -> nx_ip_total_packets_sent++;

            /* Increment the IP bytes sent count.  */
            ip_ptr -> nx_ip_total_bytes_sent +=  packet_ptr -> nx_packet_length - sizeof(NX_IP_HEADER);
#endif /* !NX_DISABLE_IP_INFO */

            /* If trace is enabled, insert this event into the trace buffer.  */
            NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_PACKET_SEND, ip_ptr, packet_ptr, packet_ptr -> nx_packet_length, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

            /* Broadcast packet.  */
            (packet_ptr -> nx_packet_ip_interface -> nx_interface_link_driver_entry) (&driver_request);

            return;
        }

        /* Determine if we have a class D multicast address.  */
        else if ((destination_ip & NX_IP_CLASS_D_MASK) == NX_IP_CLASS_D_TYPE)
        {

            /* Yes, we have a class D multicast address.  Derive the physical mapping from
               the class D address.  */
            driver_request.nx_ip_driver_physical_address_msw =  NX_IP_MULTICAST_UPPER;
            driver_request.nx_ip_driver_physical_address_lsw =  NX_IP_MULTICAST_LOWER | (destination_ip & NX_IP_MULTICAST_MASK);
            driver_request.nx_ip_driver_interface            =  packet_ptr -> nx_packet_ip_interface;

            /* Determine if the group was joined by this IP instance, and requested a packet via its loopback interface.  */
            index =  0;
            while (index < NX_MAX_MULTICAST_GROUPS)
            {

                /* Determine if the destination address matches the requested address.  */
                if (ip_ptr -> nx_ip_igmp_join_list[index] == destination_ip)
                {

                    /* Yes, break the loop!  */
                    break;
                }

                /* Increment the join list index.  */
                index++;
            }
            if (index < NX_MAX_MULTICAST_GROUPS)
            {

                /* Determine if the group has loopback enabled.  */
                if (ip_ptr -> nx_ip_igmp_group_loopback_enable[index])
                {

                    /*
                       Yes, loopback is enabled! Send the packet via
                       the loopback interface, and do not release the
                       original packet so it can be transmitted via a physical
                       interface later on.
                     */
                    _nx_ip_loopback_send(ip_ptr, packet_ptr, NX_FALSE);
                }
            }

            /* Build the driver request.  */
            driver_request.nx_ip_driver_ptr        =  ip_ptr;
            driver_request.nx_ip_driver_command    =  NX_LINK_PACKET_SEND;
            driver_request.nx_ip_driver_packet     =  packet_ptr;
            driver_request.nx_ip_driver_interface  =  packet_ptr -> nx_packet_ip_interface;

#ifndef NX_DISABLE_FRAGMENTATION
            /* Determine if fragmentation is needed.  */
            if (packet_ptr -> nx_packet_length > packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_mtu_size)
            {

                /* Fragmentation is needed, call the fragment routine if available. */
                if (ip_ptr -> nx_ip_fragment_processing)
                {

                    /* Call the IP fragment processing routine.  */
                    (ip_ptr -> nx_ip_fragment_processing)(&driver_request);
                }
                else
                {

#ifndef NX_DISABLE_IP_INFO

                    /* Increment the IP send packets dropped count.  */
                    ip_ptr -> nx_ip_send_packets_dropped++;
#endif /* !NX_DISABLE_IP_INFO */
                    /* Just release the packet.  */
                    _nx_packet_transmit_release(packet_ptr);
                }

                /* In either case, this packet send is complete, just return.  */
                return;
            }
#endif /* !NX_DISABLE_FRAGMENTATION */

#ifndef NX_DISABLE_IP_INFO

            /* Increment the IP packet sent count.  */
            ip_ptr -> nx_ip_total_packets_sent++;

            /* Increment the IP bytes sent count.  */
            ip_ptr -> nx_ip_total_bytes_sent +=  packet_ptr -> nx_packet_length - sizeof(NX_IP_HEADER);
#endif /* !NX_DISABLE_IP_INFO */

            /* If trace is enabled, insert this event into the trace buffer.  */
            NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_PACKET_SEND, ip_ptr, packet_ptr, packet_ptr -> nx_packet_length, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

            /* Send the IP packet out on the network via the attached driver.  */
            (packet_ptr -> nx_packet_ip_interface -> nx_interface_link_driver_entry) (&driver_request);

            /* Done processing Multicast packet.  Return to caller.  */
            return;
        }

        /* If we get here, the packet destination is a unicast address.  */
        destination_ip = packet_ptr -> nx_packet_next_hop_address;

        /* Look into the ARP Routing Table to derive the physical address.  */

        /* Calculate the hash index for the destination IP address.  */
        index =  (UINT)((destination_ip + (destination_ip >> 8)) & NX_ROUTE_TABLE_MASK);

        /* Disable interrupts temporarily.  */
        TX_DISABLE

        /* Determine if there is an entry for this IP address.  */
        arp_ptr =  ip_ptr -> nx_ip_arp_table[index];

        /* Determine if this arp entry matches the destination IP address.  */
        if ((arp_ptr) && (arp_ptr -> nx_arp_ip_address == destination_ip))
        {

            /* Yes, we have an existing ARP mapping entry.  */

            /* Determine if there is a physical address.  */
            if (arp_ptr -> nx_arp_physical_address_msw | arp_ptr -> nx_arp_physical_address_lsw)
            {

                /* Yes, we have a physical mapping.  Copy the physical address into the driver
                   request structure.  */
                driver_request.nx_ip_driver_physical_address_msw =  arp_ptr -> nx_arp_physical_address_msw;
                driver_request.nx_ip_driver_physical_address_lsw =  arp_ptr -> nx_arp_physical_address_lsw;
                driver_request.nx_ip_driver_interface            =  packet_ptr -> nx_packet_ip_interface;

                /* Restore interrupts.  */
                TX_RESTORE

                /* Build the driver request.  */
                driver_request.nx_ip_driver_ptr =      ip_ptr;
                driver_request.nx_ip_driver_command =  NX_LINK_PACKET_SEND;
                driver_request.nx_ip_driver_packet =   packet_ptr;

#ifndef NX_DISABLE_FRAGMENTATION
                /* Determine if fragmentation is needed.  */
                if (packet_ptr -> nx_packet_length > packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_mtu_size)
                {

                    /* Fragmentation is needed, call the fragment routine if available. */
                    if (ip_ptr -> nx_ip_fragment_processing)
                    {

                        /* Call the IP fragment processing routine.  */
                        (ip_ptr -> nx_ip_fragment_processing)(&driver_request);
                    }
                    else
                    {

#ifndef NX_DISABLE_IP_INFO

                        /* Increment the IP send packets dropped count.  */
                        ip_ptr -> nx_ip_send_packets_dropped++;
#endif /* !NX_DISABLE_IP_INFO */

                        /* Just release the packet.  */
                        _nx_packet_transmit_release(packet_ptr);
                    }

                    /* In either case, this packet send is complete, just return.  */
                    return;
                }
#endif /* !NX_DISABLE_FRAGMENTATION */

#ifndef NX_DISABLE_IP_INFO

                /* Increment the IP packet sent count.  */
                ip_ptr -> nx_ip_total_packets_sent++;

                /* Increment the IP bytes sent count.  */
                ip_ptr -> nx_ip_total_bytes_sent +=  packet_ptr -> nx_packet_length - sizeof(NX_IP_HEADER);
#endif /* !NX_DISABLE_IP_INFO */

                /* If trace is enabled, insert this event into the trace buffer.  */
                NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_PACKET_SEND, ip_ptr, packet_ptr, packet_ptr -> nx_packet_length, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

                /* Send the IP packet out on the network via the attached driver.  */
                (packet_ptr -> nx_packet_ip_interface -> nx_interface_link_driver_entry) (&driver_request);

                /* Return to caller.  */
                return;
            }
            else
            {

                /* No physical mapping available. Set the current packet's queue next pointer to NULL.  */
                packet_ptr -> nx_packet_queue_next =  NX_NULL;

                /* Determine if the queue is empty.  */
                if (arp_ptr -> nx_arp_packets_waiting == NX_NULL)
                {

                    /* Yes, we have an empty ARP packet queue.  Simply place the
                       packet at the head of the list.  */
                    arp_ptr -> nx_arp_packets_waiting =  packet_ptr;

                    /* Restore interrupts.  */
                    TX_RESTORE
                }
                else
                {

                    /* Determine how many packets are on the ARP entry's packet
                       queue and remember the last packet in the queue.  We know
                       there is at least one on the queue and another that is
                       going to be queued.  */
                    last_packet =  arp_ptr -> nx_arp_packets_waiting;
                    queued_count = 1;
                    while (last_packet -> nx_packet_queue_next)
                    {

                        /* Increment the queued count.  */
                        queued_count++;

                        /* Yes, move to the next packet in the queue.  */
                        last_packet =  last_packet -> nx_packet_queue_next;
                    }

                    /* Place the packet at the end of the list.  */
                    last_packet -> nx_packet_queue_next =  packet_ptr;

                    /* Default the remove packet pointer to NULL.  */
                    remove_packet =  NX_NULL;

                    /* Determine if the packets queued has exceeded the queue
                       depth.  */
                    if (queued_count >= NX_ARP_MAX_QUEUE_DEPTH)
                    {

                        /* Save the packet pointer at the head of the list.  */
                        remove_packet =  arp_ptr -> nx_arp_packets_waiting;

                        /* Remove the packet from the ARP queue.  */
                        arp_ptr -> nx_arp_packets_waiting =  remove_packet -> nx_packet_queue_next;

                        /* Clear the remove packet queue next pointer.  */
                        remove_packet -> nx_packet_queue_next =  NX_NULL;

#ifndef NX_DISABLE_IP_INFO

                        /* Increment the IP transmit resource error count.  */
                        ip_ptr -> nx_ip_transmit_resource_errors++;

                        /* Increment the IP send packets dropped count.  */
                        ip_ptr -> nx_ip_send_packets_dropped++;
#endif /* !NX_DISABLE_IP_INFO */
                    }

                    /* Restore interrupts.  */
                    TX_RESTORE

                    /* Determine if there is a packet to remove.  */
                    if (remove_packet)
                    {

                        /* Yes, the packet queue depth for this ARP entry was exceeded
                           so release the packet that was removed from the queue.  */
                        _nx_packet_transmit_release(remove_packet);
                    }
                }

                /* Return to caller.  */
                return;
            }
        }
        else
        {

            /* At this point, we need to search the ARP list for a match for the
               destination IP.  */

            /* First, restore interrupts.  */
            TX_RESTORE

            /* Pickup the first ARP entry.  */
            arp_ptr =  ip_ptr -> nx_ip_arp_table[index];

            /* Loop to look for an ARP match.  */
            while (arp_ptr)
            {

                /* Check for an IP match.  */
                if (arp_ptr -> nx_arp_ip_address == destination_ip)
                {

                    /* Yes, we found a match.  Get out of the loop!  */
                    break;
                }

                /* Move to the next active ARP entry.  */
                arp_ptr =  arp_ptr -> nx_arp_active_next;

                /* Determine if we are at the end of the ARP list.  */
                if (arp_ptr == ip_ptr -> nx_ip_arp_table[index])
                {
                    /* Clear the ARP pointer.  */
                    arp_ptr =  NX_NULL;
                    break;
                }
            }

            /* Determine if we actually found a matching ARP entry.  */
            if (arp_ptr)
            {

                /* Yes, we found an ARP entry.  Now check and see if
                   it has an actual physical address.  */
                if (arp_ptr -> nx_arp_physical_address_msw | arp_ptr -> nx_arp_physical_address_lsw)
                {

                    /* Yes, we have a physical mapping.  Copy the physical address into the driver
                       request structure.  */
                    driver_request.nx_ip_driver_physical_address_msw =  arp_ptr -> nx_arp_physical_address_msw;
                    driver_request.nx_ip_driver_physical_address_lsw =  arp_ptr -> nx_arp_physical_address_lsw;

                    /* Disable interrupts.  */
                    TX_DISABLE

                    /* Move this ARP entry to the head of the list.  */
                    ip_ptr -> nx_ip_arp_table[index] =  arp_ptr;

                    /* Restore interrupts.  */
                    TX_RESTORE

                    /* Build the driver request message.  */
                    driver_request.nx_ip_driver_ptr        =  ip_ptr;
                    driver_request.nx_ip_driver_command    =  NX_LINK_PACKET_SEND;
                    driver_request.nx_ip_driver_packet     =  packet_ptr;
                    driver_request.nx_ip_driver_interface  =  packet_ptr -> nx_packet_ip_interface;

#ifndef NX_DISABLE_FRAGMENTATION
                    /* Determine if fragmentation is needed.  */
                    if (packet_ptr -> nx_packet_length > packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_mtu_size)
                    {

                        /* Fragmentation is needed, call the fragment routine if available. */
                        if (ip_ptr -> nx_ip_fragment_processing)
                        {

                            /* Call the IP fragment processing routine.  */
                            (ip_ptr -> nx_ip_fragment_processing)(&driver_request);
                        }
                        else
                        {

#ifndef NX_DISABLE_IP_INFO

                            /* Increment the IP send packets dropped count.  */
                            ip_ptr -> nx_ip_send_packets_dropped++;
#endif /* !NX_DISABLE_IP_INFO */

                            /* Just release the packet.  */
                            _nx_packet_transmit_release(packet_ptr);
                        }

                        /* In either case, this packet send is complete, just return.  */
                        return;
                    }
#endif /* !NX_DISABLE_FRAGMENTATION */

#ifndef NX_DISABLE_IP_INFO

                    /* Increment the IP packet sent count.  */
                    ip_ptr -> nx_ip_total_packets_sent++;

                    /* Increment the IP bytes sent count.  */
                    ip_ptr -> nx_ip_total_bytes_sent +=  packet_ptr -> nx_packet_length - sizeof(NX_IP_HEADER);
#endif /* !NX_DISABLE_IP_INFO */

                    /* If trace is enabled, insert this event into the trace buffer.  */
                    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_PACKET_SEND, ip_ptr, packet_ptr, packet_ptr -> nx_packet_length, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

                    /* Send the IP packet out on the network via the attached driver.  */
                    (packet_ptr -> nx_packet_ip_interface -> nx_interface_link_driver_entry) (&driver_request);

                    /* Return to caller.  */
                    return;
                }
                else
                {

                    /* We don't have physical mapping.  */

                    /* Disable interrupts.  */
                    TX_DISABLE

                    /* Ensure the current packet's queue next pointer to NULL.  */
                    packet_ptr -> nx_packet_queue_next =  NX_NULL;

                    /* Determine if the queue is empty.  */
                    if (arp_ptr -> nx_arp_packets_waiting == NX_NULL)
                    {

                        /* Yes, we have an empty ARP packet queue.  Simply place the
                           packet at the head of the list.  */
                        arp_ptr -> nx_arp_packets_waiting =  packet_ptr;

                        /* Restore interrupts.  */
                        TX_RESTORE
                    }
                    else
                    {


                        /* Determine how many packets are on the ARP entry's packet
                           queue and remember the last packet in the queue.  We know
                           there is at least one on the queue and another that is
                           going to be queued.  */
                        last_packet =  arp_ptr -> nx_arp_packets_waiting;
                        queued_count = 1;
                        while (last_packet -> nx_packet_queue_next)
                        {

                            /* Increment the queued count.  */
                            queued_count++;

                            /* Yes, move to the next packet in the queue.  */
                            last_packet =  last_packet -> nx_packet_queue_next;
                        }

                        /* Place the packet at the end of the list.  */
                        last_packet -> nx_packet_queue_next =  packet_ptr;

                        /* Default the remove packet pointer to NULL.  */
                        remove_packet =  NX_NULL;

                        /* Determine if the packets queued has exceeded the queue
                           depth.  */
                        if (queued_count >= NX_ARP_MAX_QUEUE_DEPTH)
                        {

                            /* Save the packet pointer at the head of the list.  */
                            remove_packet =  arp_ptr -> nx_arp_packets_waiting;

                            /* Remove the packet from the ARP queue.  */
                            arp_ptr -> nx_arp_packets_waiting =  remove_packet -> nx_packet_queue_next;

                            /* Clear the remove packet queue next pointer.  */
                            remove_packet -> nx_packet_queue_next =  NX_NULL;

#ifndef NX_DISABLE_IP_INFO

                            /* Increment the IP transmit resource error count.  */
                            ip_ptr -> nx_ip_transmit_resource_errors++;

                            /* Increment the IP send packets dropped count.  */
                            ip_ptr -> nx_ip_send_packets_dropped++;
#endif /* !NX_DISABLE_IP_INFO */
                        }

                        /* Restore interrupts.  */
                        TX_RESTORE

                        /* Determine if there is a packet to remove.  */
                        if (remove_packet)
                        {

                            /* Yes, the packet queue depth for this ARP entry was exceeded
                               so release the packet that was removed from the queue.  */
                            _nx_packet_transmit_release(remove_packet);
                        }
                    }

                    /* Return to caller.  */
                    return;
                }
            }
            else
            {

                /* No ARP entry was found.  We need to allocate a new ARP entry, populate it, and
                   initiate an ARP request to get the specific physical mapping.  */

                /* Allocate a new ARP entry.  */
                if ((!ip_ptr -> nx_ip_arp_allocate) ||
                    ((ip_ptr -> nx_ip_arp_allocate)(ip_ptr, &(ip_ptr -> nx_ip_arp_table[index]))))
                {

                    /* Error, release the protection and the packet.  */

#ifndef NX_DISABLE_IP_INFO

                    /* Increment the IP transmit resource error count.  */
                    ip_ptr -> nx_ip_transmit_resource_errors++;

                    /* Increment the IP send packets dropped count.  */
                    ip_ptr -> nx_ip_send_packets_dropped++;
#endif /* !NX_DISABLE_IP_INFO */

                    /* Release the packet.  */
                    _nx_packet_transmit_release(packet_ptr);

                    /* Just return!  */
                    return;
                }

                /* Otherwise, setup a pointer to the new ARP entry.  */
                arp_ptr =  (ip_ptr -> nx_ip_arp_table[index]) -> nx_arp_active_previous;

                /* Setup the IP address and clear the physical mapping.  */
                arp_ptr -> nx_arp_ip_address           =  destination_ip;
                arp_ptr -> nx_arp_physical_address_msw =  0;
                arp_ptr -> nx_arp_physical_address_lsw =  0;
                arp_ptr -> nx_arp_entry_next_update    =  NX_ARP_UPDATE_RATE;
                arp_ptr -> nx_arp_retries              =  0;
                arp_ptr -> nx_arp_ip_interface         =  packet_ptr -> nx_packet_ip_interface;

                /* Ensure the queue next pointer is NULL for the packet before it
                   is placed on the ARP waiting queue.  */
                packet_ptr -> nx_packet_queue_next =  NX_NULL;

                /* Queue the packet for output.  */
                arp_ptr -> nx_arp_packets_waiting =  packet_ptr;

                /* Call ARP send to send an ARP request.  */
                (ip_ptr -> nx_ip_arp_packet_send)(ip_ptr, destination_ip, packet_ptr -> nx_packet_ip_interface);
                return;
            }
        }
    }
    else
    {

        /* This IP interface does not require any IP-to-physical mapping.  */

        /* Build the driver request.  */
        driver_request.nx_ip_driver_ptr        =      ip_ptr;
        driver_request.nx_ip_driver_command    =  NX_LINK_PACKET_SEND;
        driver_request.nx_ip_driver_packet     =  packet_ptr;
        driver_request.nx_ip_driver_interface  =  packet_ptr -> nx_packet_ip_interface;

#ifndef NX_DISABLE_FRAGMENTATION
        /* Determine if fragmentation is needed.  */
        if (packet_ptr -> nx_packet_length > packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_mtu_size)
        {

            /* Fragmentation is needed, call the fragment routine if available. */
            if (ip_ptr -> nx_ip_fragment_processing)
            {

                /* Call the IP fragment processing routine.  */
                (ip_ptr -> nx_ip_fragment_processing)(&driver_request);
            }
            else
            {

#ifndef NX_DISABLE_IP_INFO

                /* Increment the IP send packets dropped count.  */
                ip_ptr -> nx_ip_send_packets_dropped++;
#endif /* !NX_DISABLE_IP_INFO */

                /* Just release the packet.  */
                _nx_packet_transmit_release(packet_ptr);
            }

            /* In either case, this packet send is complete, just return.  */
            return;
        }
#endif /* !NX_DISABLE_FRAGMENTATION */

#ifndef NX_DISABLE_IP_INFO

        /* Increment the IP packet sent count.  */
        ip_ptr -> nx_ip_total_packets_sent++;

        /* Increment the IP bytes sent count.  */
        ip_ptr -> nx_ip_total_bytes_sent +=  packet_ptr -> nx_packet_length - sizeof(NX_IP_HEADER);
#endif /* !NX_DISABLE_IP_INFO */

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_PACKET_SEND, ip_ptr, packet_ptr, packet_ptr -> nx_packet_length, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

        /* No mapping driver.  Just send the packet out!  */
        (packet_ptr -> nx_packet_ip_interface -> nx_interface_link_driver_entry) (&driver_request);
    }
}

