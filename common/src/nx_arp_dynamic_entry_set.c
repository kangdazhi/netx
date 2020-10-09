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
/**   Address Resolution Protocol (ARP)                                   */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_arp.h"
#include "nx_ip.h"
#include "nx_packet.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_arp_dynamic_entry_set                           PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function allocates an ARP dynamic entry for the application    */
/*    and assigns the specified IP to hardware mapping. If the specified  */
/*    hardware address is zero, an actual ARP request will be sent out.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    ip_address                            IP Address to bind to         */
/*    physical_msw                          Physical address MSW          */
/*    physical_lsw                          Physical address LSW          */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_arp_entry_allocate                Allocate an ARP entry         */
/*    _nx_arp_packet_send                   Send ARP request              */
/*    _nx_packet_transmit_release           Release ARP queued packet     */
/*    tx_mutex_get                          Obtain protection mutex       */
/*    tx_mutex_put                          Release protection mutex      */
/*    _nx_ip_route_find                     Find suitable outgoing        */
/*                                            interface                   */
/*    (nx_ip_fragment_processing)           Fragment processing           */
/*    (ip_link_driver)                      User supplied link driver     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
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
UINT  _nx_arp_dynamic_entry_set(NX_IP *ip_ptr, ULONG ip_address,
                                ULONG physical_msw, ULONG physical_lsw)
{

TX_INTERRUPT_SAVE_AREA
NX_ARP       *arp_ptr;
NX_ARP       *search_ptr;
NX_ARP       *arp_list_head;
UINT          index;
UINT          status;
NX_IP_DRIVER  driver_request;
NX_PACKET    *queued_list_head;
NX_PACKET    *packet_ptr;
NX_INTERFACE *nx_interface = NX_NULL;
ULONG         next_hop_address = 0;

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_ARP_DYNAMIC_ENTRY_SET, ip_ptr, ip_address, physical_msw, physical_lsw, NX_TRACE_ARP_EVENTS, 0, 0)

    /* Make sure the destination address is directly accessible. */
    if ((_nx_ip_route_find(ip_ptr, ip_address, &nx_interface, &next_hop_address) != NX_SUCCESS) ||
        (next_hop_address != ip_address))
    {

        return(NX_IP_ADDRESS_ERROR);
    }


    /* Obtain protection on this IP instance for access into the ARP dynamic
       list.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Calculate the hash index for the specified IP address.  */
    index =  (UINT)((ip_address + (ip_address >> 8)) & NX_ROUTE_TABLE_MASK);

    /* Pickup the head pointer of the ARP entries for this IP instance.  */
    arp_list_head =  ip_ptr -> nx_ip_arp_table[index];

    /* Search the ARP list for the same IP address.  */
    search_ptr =  arp_list_head;
    arp_ptr =     NX_NULL;
    while (search_ptr)
    {

        /* Determine if there is a duplicate IP address.  */
        if (search_ptr -> nx_arp_ip_address == ip_address)
        {

            /* Yes, the IP address matches, setup the ARP entry pointer.  */
            arp_ptr =  search_ptr;

            /* Get out of the loop.  */
            break;
        }

        /* Move to the next entry in the active list.  */
        search_ptr =  search_ptr -> nx_arp_active_next;

        /* Determine if the search pointer is back at the head of
           the list.  */
        if (search_ptr == arp_list_head)
        {

            /* End of the ARP list, end the search.  */
            break;
        }
    }

    /* Determine if we didn't find an ARP entry and need to allocate a new
       dynamic entry.  */
    if (arp_ptr == NX_NULL)
    {

        /* No matching IP address in the ARP cache.  */

        /* Allocate a dynamic ARP entry.  */
        status =  _nx_arp_entry_allocate(ip_ptr, &(ip_ptr -> nx_ip_arp_table[index]));

        /* Determine if an error occurred.  */
        if (status != NX_SUCCESS)
        {

            /* Release the mutex.  */
            tx_mutex_put(&(ip_ptr -> nx_ip_protection));

            /* Return the error status.  */
            return(status);
        }

        /* Otherwise, setup a pointer to the new ARP entry.  The newly allocated
           ARP entry was allocated at the end of the ARP list so it should be
           referenced using the previous pointer from the list head.  */
        arp_ptr =  (ip_ptr -> nx_ip_arp_table[index]) -> nx_arp_active_previous;
    }

    /* Setup the IP address and clear the physical mapping.  */
    arp_ptr -> nx_arp_ip_address =            ip_address;
    arp_ptr -> nx_arp_physical_address_msw =  physical_msw;
    arp_ptr -> nx_arp_physical_address_lsw =  physical_lsw;
    arp_ptr -> nx_arp_retries =               0;
    arp_ptr -> nx_arp_entry_next_update =     NX_ARP_EXPIRATION_RATE;
    arp_ptr -> nx_arp_ip_interface =          nx_interface;

    /* Determine if a physical address was supplied.  */
    if ((physical_msw | physical_lsw) == 0)
    {

        /* Since there isn't physical mapping, change the update rate
           for possible ARP retries.  */
        arp_ptr -> nx_arp_entry_next_update =     NX_ARP_UPDATE_RATE;


        /* The physical address was not specified so send an
           ARP request for the selected IP address.  */
        _nx_arp_packet_send(ip_ptr, ip_address, nx_interface);

        /* Release the protection on the ARP list.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        /* Return status to the caller.  */
        return(NX_SUCCESS);
    }
    else
    {

        /* A physical address was supplied.  */

        /* Initialize the queued list head to NULL.  */
        queued_list_head =  NX_NULL;

        /* Determine if this ARP entry has a packet queued up for
           sending.  */

        /* Disable interrupts before checking.  */
        TX_DISABLE

        /* Look at the ARP packet queue pointer.  */
        if (arp_ptr -> nx_arp_packets_waiting)
        {

            /* Pickup the packet pointer and clear the ARP queue pointer.  */
            queued_list_head =  arp_ptr -> nx_arp_packets_waiting;
            arp_ptr -> nx_arp_packets_waiting =  NX_NULL;
        }

        /* Restore previous interrupt posture.  */
        TX_RESTORE

        /* Are there any packets queued to send?  */
        while (queued_list_head)
        {

            /* Pickup the first entry on the list.  */
            packet_ptr =  queued_list_head;

            /* Move to the next entry on the ARP packet queue.  */
            queued_list_head =  queued_list_head -> nx_packet_queue_next;

            /* Clear the packet's queue next pointer.  */
            packet_ptr -> nx_packet_queue_next =  NX_NULL;

            packet_ptr -> nx_packet_ip_interface = nx_interface;

            /* Build the driver request packet.  */
            driver_request.nx_ip_driver_physical_address_msw =  physical_msw;
            driver_request.nx_ip_driver_physical_address_lsw =  physical_lsw;
            driver_request.nx_ip_driver_ptr                  =  ip_ptr;
            driver_request.nx_ip_driver_command              =  NX_LINK_PACKET_SEND;
            driver_request.nx_ip_driver_packet               =  packet_ptr;
            driver_request.nx_ip_driver_interface            =  packet_ptr -> nx_packet_ip_interface;

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
#endif

                    /* Just release the packet.  */
                    _nx_packet_transmit_release(packet_ptr);
                }
            }
            else
            {

#ifndef NX_DISABLE_IP_INFO

                /* Increment the IP packet sent count.  */
                ip_ptr -> nx_ip_total_packets_sent++;

                /* Increment the IP bytes sent count.  */
                ip_ptr -> nx_ip_total_bytes_sent +=  packet_ptr -> nx_packet_length - sizeof(NX_IP_HEADER);
#endif

                /* If trace is enabled, insert this event into the trace buffer.  */
                NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_PACKET_SEND, ip_ptr, packet_ptr, packet_ptr -> nx_packet_length, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

                /* Send the queued IP packet out on the network via the attached driver.  */
                (packet_ptr -> nx_packet_ip_interface -> nx_interface_link_driver_entry) (&driver_request);
            }
        }

        /* Release the protection on the ARP list.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        /* Return status to the caller.  */
        return(NX_SUCCESS);
    }
}

