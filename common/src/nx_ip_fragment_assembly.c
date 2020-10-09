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


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_fragment_assemble                            PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes the received fragment queue and attempts to */
/*    reassemble fragmented IP datagrams.  Once a datagram is reassembled */
/*    it is dispatched to the appropriate component.                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP instance        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_release                    Release packet                */
/*    (ip_tcp_packet_receive)               Receive a TCP packet          */
/*    (ip_udp_packet_receive)               Receive a UDP packet          */
/*    (ip_icmp_packet_receive)              Receive a ICMP packet         */
/*    (ip_igmp_packet_receive)              Receive a IGMP packet         */
/*    (ip_raw_ip_raw_packet_processing)     Process a Raw IP packet       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
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
VOID  _nx_ip_fragment_assembly(NX_IP *ip_ptr)
{
TX_INTERRUPT_SAVE_AREA

NX_PACKET    *new_fragment_head;
NX_PACKET    *current_fragment;
NX_PACKET    *previous_fragment =  NX_NULL;
NX_PACKET    *fragment_head;
NX_PACKET    *search_ptr;
NX_PACKET    *previous_ptr;
NX_PACKET    *found_ptr;
NX_IP_HEADER *search_header;
NX_IP_HEADER *current_header;
ULONG         current_id;
ULONG         current_offset;
ULONG         protocol;
UCHAR         incomplete;


    /* Disable interrupts.  */
    TX_DISABLE

    /* Remove the packets from the incoming IP fragment queue.  */
    new_fragment_head =  ip_ptr -> nx_ip_received_fragment_head;
    ip_ptr -> nx_ip_received_fragment_head =  NX_NULL;
    ip_ptr -> nx_ip_received_fragment_tail =  NX_NULL;

    /* Restore interrupts.  */
    TX_RESTORE

    /* Process each IP packet in the received IP fragment queue.  */
    while (new_fragment_head)
    {

        /* Setup the current fragment pointer.  */
        current_fragment =  new_fragment_head;

        /* Move the head pointer.  */
        new_fragment_head =  new_fragment_head -> nx_packet_queue_next;

        /* Setup header pointer for this packet.  */
        current_header =  (NX_IP_HEADER *)current_fragment -> nx_packet_prepend_ptr;

        /* Pickup the ID of this fragment.  */
        current_id =  (current_header ->  nx_ip_header_word_1 >> NX_SHIFT_BY_16);

        /* Set the found pointer to NULL.  */
        found_ptr =  NX_NULL;

        /* Does the assembly list have anything in it?  */
        if (ip_ptr -> nx_ip_fragment_assembly_head)
        {

            /* Yes, we need to search the assembly queue to see if this fragment belongs
               to another fragment.  */
            search_ptr =    ip_ptr -> nx_ip_fragment_assembly_head;
            previous_fragment =  NX_NULL;
            while (search_ptr)
            {

                /* Setup a pointer to the IP header of the packet in the assembly list.  */
                search_header =  (NX_IP_HEADER *)search_ptr -> nx_packet_prepend_ptr;

                /* Determine if the IP header fields match. RFC 791 Section 3.2 recommends that packet
                   fragments be compared for source IP, destination IP, protocol and IP header ID.  */
                if ((current_id == (search_header -> nx_ip_header_word_1 >> NX_SHIFT_BY_16)) &&
                    ((search_header -> nx_ip_header_word_2 & NX_IP_PROTOCOL_MASK) ==
                     (current_header -> nx_ip_header_word_2 & NX_IP_PROTOCOL_MASK)) &&
                    (search_header -> nx_ip_header_source_ip == current_header -> nx_ip_header_source_ip) &&
                    (search_header -> nx_ip_header_destination_ip == current_header -> nx_ip_header_destination_ip))
                {

                    /* Yes, we found a match, just set the found_ptr and get out of
                       this loop!  */
                    found_ptr =  search_ptr;
                    break;
                }

                /* Remember the previous pointer.  */
                previous_fragment =  search_ptr;

                /* Move to the next IP fragment in the re-assembly queue.  */
                search_ptr =  search_ptr -> nx_packet_queue_next;
            }
        }

        /* Was another IP packet fragment found?  */
        if (found_ptr)
        {

            /* Save the fragment head pointer.  */
            fragment_head =  found_ptr;

            /* Pickup the offset of the new IP fragment.  */
            current_offset =  current_header -> nx_ip_header_word_1 & NX_IP_OFFSET_MASK;

            /* Another packet fragment was found...  find the proper place in the list
               for this packet and check for complete re-assembly.  */

            /* Setup the previous pointer.  Note that the search pointer still points
               to the first fragment in the list.  */
            previous_ptr =  NX_NULL;
            search_ptr =    found_ptr;

            /* Loop to walk through the fragment list.  */
            do
            {

                /* Pickup a pointer to the IP header of the fragment.  */
                search_header =  (NX_IP_HEADER *)search_ptr -> nx_packet_prepend_ptr;

                /* Determine if the incoming IP fragment goes before this packet.  */
                if (current_offset < (search_header -> nx_ip_header_word_1 & NX_IP_OFFSET_MASK))
                {

                    /* Yes, break out of the loop and insert the current packet.  */
                    break;
                }

                /* Otherwise, move the search and previous pointers to the next fragment in the
                   chain.  */
                previous_ptr =  search_ptr;
                search_ptr =    search_ptr -> nx_packet_fragment_next;
            } while (search_ptr);

            /* At this point, the previous pointer determines where to place the new fragment.  */
            if (previous_ptr)
            {

                /* Add new fragment after the previous ptr.  */
                current_fragment -> nx_packet_fragment_next =  previous_ptr -> nx_packet_fragment_next;
                previous_ptr -> nx_packet_fragment_next =      current_fragment;
            }
            else
            {

                /* This packet needs to be inserted at the front of the fragment chain.  */
                current_fragment -> nx_packet_queue_next =     fragment_head -> nx_packet_queue_next;
                current_fragment -> nx_packet_fragment_next =  fragment_head;
                if (previous_fragment)
                {

                    /* We need to link up a different IP packet fragment chain that is in
                       front of this one on the re-assembly queue.  */
                    previous_fragment -> nx_packet_queue_next =  current_fragment;
                }
                else
                {

                    /* Nothing prior to this IP fragment chain, we need to just change the
                       list header.  */
                    ip_ptr -> nx_ip_fragment_assembly_head =  current_fragment;

                    /* Clear the timeout fragment pointer.  */
                    ip_ptr -> nx_ip_timeout_fragment =  NX_NULL;
                }

                /* Determine if we need to adjust the tail pointer.  */
                if (fragment_head == ip_ptr -> nx_ip_fragment_assembly_tail)
                {

                    /* Setup the new tail pointer.  */
                    ip_ptr -> nx_ip_fragment_assembly_tail =  current_fragment;
                }

                /* Setup the new fragment head.  */
                fragment_head =  current_fragment;
            }

            /* At this point, the new IP fragment is in its proper place on the re-assembly
               list.  We now need to walk the list and determine if all the fragments are
               present.  */

            /* Setup the search pointer to the fragment head.  */
            search_ptr =  fragment_head;

            /* Set the current expected offset to 0.  */
            current_offset =  0;

            /* Loop through the packet chain to see if all the fragments have
               arrived.  */
            incomplete = 0;
            do
            {

                /* Build the IP header pointer.  */
                search_header =  (NX_IP_HEADER *)search_ptr -> nx_packet_prepend_ptr;

                /* Check for the expected current offset.  */
                if (current_offset != (search_header -> nx_ip_header_word_1 & NX_IP_OFFSET_MASK))
                {

                    /* There are still more fragments necessary to reassemble this packet
                       so just return.  */
                    incomplete = 1;
                    break;
                }

                /* Calculate the next expected offset.  */
                current_offset =  current_offset +
                    ((search_header -> nx_ip_header_word_0 & NX_LOWER_16_MASK) - sizeof(NX_IP_HEADER)) / NX_IP_ALIGN_FRAGS;

                /* Move the search pointer forward to the next fragment.  */
                search_ptr =    search_ptr -> nx_packet_fragment_next;
            } while (search_ptr);

            if (incomplete)
            {
                continue;
            }

            /* At this point the search header points to the last fragment in the chain.  In
               order for the packet to be complete, the "more fragments" bit in its IP header
               must be clear.  */
            if (search_header -> nx_ip_header_word_1 & NX_IP_MORE_FRAGMENT)
            {

                /* There are still more fragments necessary to re-assembly this packet
                   so just return.  */
                continue;
            }

            /* If we get here, the necessary fragments to reassemble the packet
               are indeed available.  We now need to loop through the packet and reassemble
               it.  */
            search_ptr =       fragment_head -> nx_packet_fragment_next;

            /* Loop through the fragments and assemble the IP fragment.  */
            while (search_ptr)
            {

                /* Accumulate the new length into the head packet.  */
                fragment_head -> nx_packet_length =  fragment_head -> nx_packet_length +
                    search_ptr -> nx_packet_length - sizeof(NX_IP_HEADER);

                /* Position past the IP header in the subsequent packets.  */
                search_ptr -> nx_packet_prepend_ptr =  search_ptr -> nx_packet_prepend_ptr +
                    sizeof(NX_IP_HEADER);

                /* Link the addition fragment to the head fragment.  */
                if (fragment_head -> nx_packet_last)
                {
                    (fragment_head -> nx_packet_last) -> nx_packet_next =  search_ptr;
                }
                else
                {
                    fragment_head -> nx_packet_next =  search_ptr;
                }
                if (search_ptr -> nx_packet_last)
                {
                    fragment_head -> nx_packet_last =  search_ptr -> nx_packet_last;
                }
                else
                {
                    fragment_head -> nx_packet_last =  search_ptr;
                }

                /* Move to the next fragment in the chain.  */
                search_ptr =  search_ptr -> nx_packet_fragment_next;
            }

            /* The packet is now reassembled under the fragment head pointer.  It must now
               be removed from the re-assembly list.  */
            if (previous_fragment)
            {

                /* Remove the fragment from a position other than the head of the assembly list.  */
                previous_fragment -> nx_packet_queue_next =  fragment_head -> nx_packet_queue_next;
            }
            else
            {

                /* Modify the head of the re-assembly list.  */
                ip_ptr -> nx_ip_fragment_assembly_head =  fragment_head -> nx_packet_queue_next;

                /* Clear the timeout fragment pointer since we are removing the first
                   fragment (the oldest) on the assembly list.  */
                ip_ptr -> nx_ip_timeout_fragment =  NX_NULL;
            }

            /* Determine if we need to adjust the tail pointer.  */
            if (fragment_head == ip_ptr -> nx_ip_fragment_assembly_tail)
            {

                /* Setup the new tail pointer.  */
                ip_ptr -> nx_ip_fragment_assembly_tail =  previous_fragment;
            }

            /* We are now ready to dispatch this packet just like the normal IP receive packet
               processing.  */

            /* Build a pointer to the IP header.  */
            current_header =  (NX_IP_HEADER *)fragment_head -> nx_packet_prepend_ptr;

            /* Determine what protocol the current IP datagram is.  */
            protocol =  current_header -> nx_ip_header_word_2 & NX_IP_PROTOCOL_MASK;

            /* Remove the IP header from the packet.  */
            fragment_head -> nx_packet_prepend_ptr =  fragment_head -> nx_packet_prepend_ptr + sizeof(NX_IP_HEADER);

            /* Adjust the length.  */
            fragment_head -> nx_packet_length =  fragment_head -> nx_packet_length - sizeof(NX_IP_HEADER);

#ifndef NX_DISABLE_IP_INFO

            /* Increment the number of packets reassembled.  */
            ip_ptr -> nx_ip_packets_reassembled++;

            /* Increment the number of packets delivered.  */
            ip_ptr -> nx_ip_total_packets_delivered++;

            /* Increment the IP packet bytes received (not including the header).  */
            ip_ptr -> nx_ip_total_bytes_received +=  fragment_head -> nx_packet_length;
#endif

            /* Determine if RAW IP is supported.  */
            if (ip_ptr -> nx_ip_raw_ip_processing)
            {

                /* Call the raw IP packet processing routine.  */
                (ip_ptr -> nx_ip_raw_ip_processing)(ip_ptr, fragment_head);
            }

            /* Dispatch the protocol...  Have we found a UDP packet?  */
            else if ((protocol == NX_IP_UDP) && (ip_ptr -> nx_ip_udp_packet_receive))
            {

                /* Yes, a UDP packet is present, dispatch to the appropriate UDP handler
                   if present.  */
                (ip_ptr -> nx_ip_udp_packet_receive)(ip_ptr, fragment_head);
            }
            /* Is a TCP packet present?  */
            else if ((protocol == NX_IP_TCP) && (ip_ptr -> nx_ip_tcp_packet_receive))
            {

                /* Yes, a TCP packet is present, dispatch to the appropriate TCP handler
                   if present.  */
                (ip_ptr -> nx_ip_tcp_packet_receive)(ip_ptr, fragment_head);
            }
            /* Is a ICMP packet present?  */
            else if ((protocol == NX_IP_ICMP) && (ip_ptr -> nx_ip_icmp_packet_receive))
            {

                /* Yes, a ICMP packet is present, dispatch to the appropriate ICMP handler
                   if present.  */
                (ip_ptr -> nx_ip_icmp_packet_receive)(ip_ptr, fragment_head);
            }
            else if ((protocol == NX_IP_IGMP) && (ip_ptr -> nx_ip_igmp_packet_receive))
            {

                /* Yes, a IGMP packet is present, dispatch to the appropriate ICMP handler
                   if present.  */
                (ip_ptr -> nx_ip_igmp_packet_receive)(ip_ptr, fragment_head);
            }
            else
            {

#ifndef NX_DISABLE_IP_INFO

                /* Decrement the number of packets delivered.  */
                ip_ptr -> nx_ip_total_packets_delivered--;

                /* Decrement the IP packet bytes received (not including the header).  */
                ip_ptr -> nx_ip_total_bytes_received -=  fragment_head -> nx_packet_length;

                /* Increment the IP unknown protocol count.  */
                ip_ptr -> nx_ip_unknown_protocols_received++;

                /* Increment the IP receive packets dropped count.  */
                ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

                /* Toss the IP packet since we don't know what to do with it!  */
                _nx_packet_release(fragment_head);
            }
        }
        else
        {

            /* No other packet was found on the re-assembly list so this packet must be the
               first one of a new IP packet.  Just add it to the end of the assembly queue.  */
            if (ip_ptr -> nx_ip_fragment_assembly_head)
            {

                /* Re-assembly list is not empty.  Just place this IP packet at the
                   end of the IP fragment assembly list.  */
                ip_ptr -> nx_ip_fragment_assembly_tail -> nx_packet_queue_next =  current_fragment;
                ip_ptr -> nx_ip_fragment_assembly_tail =                          current_fragment;
                current_fragment -> nx_packet_queue_next =                        NX_NULL;
                current_fragment -> nx_packet_fragment_next =                     NX_NULL;
            }
            else
            {

                /* First IP fragment on the assembly list.  Setup the head and tail pointers to
                   this packet.  */
                ip_ptr -> nx_ip_fragment_assembly_head =        current_fragment;
                ip_ptr -> nx_ip_fragment_assembly_tail =        current_fragment;
                current_fragment -> nx_packet_queue_next =      NX_NULL;
                current_fragment -> nx_packet_fragment_next =   NX_NULL;
            }
        }
    }
}

