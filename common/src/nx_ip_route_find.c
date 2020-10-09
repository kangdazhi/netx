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


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_route_find                                   PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function finds an outgoing interface and the next hop address  */
/*     for a given destination address.  Caller may also set desired      */
/*     interface information in nx_ip_interface parameter.  For Multicast */
/*     or limited broadcast, this routine uses primary interface if       */
/*     a hint was not set by the caller.  For directed broadcast or       */
/*     unicast destination, the hint is ignored and the proper outgoing   */
/*     interface is selected.                                             */
/*                                                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                IN              Pointer to IP instance        */
/*    destination_address   IN              Destination Address           */
/*    nx_ip_interface       OUT             Interface to use, must point  */
/*                                            to valid storage space.     */
/*    next_hop_address      OUT             IP address for the next hop,  */
/*                                            must point to valid storage */
/*                                            space.                      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Operation was successful      */
/*                                            or not.                     */
/*  CALLS                                                                 */
/*                                                                        */
/*    [nx_ip_find_route_process]            Search the static routing     */
/*                                            table.                      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_arp_dynamic_entry_set.c           ARP entry set                 */
/*    _nx_icmp_ping                         Transmit ICMP echo request    */
/*    _nx_ip_packet_send                    IP packet transmit            */
/*    _nx_tcp_client_socket_connect         TCP Client socket connection  */
/*    _nx_udp_socket_send                   UDP packet send               */
/*                                                                        */
/*  NOTE:                                                                 */
/*                                                                        */
/*    None                                                                */
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
ULONG  _nx_ip_route_find(NX_IP *ip_ptr, ULONG destination_address, NX_INTERFACE **nx_ip_interface, ULONG *next_hop_address)
{

NX_INTERFACE *nx_interface;
ULONG         i;

    /* Determine whether or not destination_address is multicast or directed broadcast. */
    if (((destination_address & NX_IP_CLASS_D_MASK) == NX_IP_CLASS_D_TYPE) ||
        (destination_address  == NX_IP_LIMITED_BROADCAST))
    {
        *next_hop_address = destination_address;
        /* If caller did not set the nx_ip_interface value, use
           the primary interface for transmission.  */
        if (*nx_ip_interface == NX_NULL)
        {
            *nx_ip_interface = &(ip_ptr -> nx_ip_interface[0]);
        }

        return(NX_SUCCESS);
    }



#ifdef NX_ENABLE_IP_STATIC_ROUTING


    /* Search through the routing table, check whether the entry exists or not. */
    for (i = 0; i < ip_ptr -> nx_ip_routing_table_entry_count; i++)
    {
        if (ip_ptr -> nx_ip_routing_table[i].nx_ip_routing_entry_destination_ip == (destination_address & ip_ptr -> nx_ip_routing_table[i].nx_ip_routing_entry_net_mask))
        {
            *nx_ip_interface = ip_ptr -> nx_ip_routing_table[i].nx_ip_routing_entry_ip_interface;
            *next_hop_address = ip_ptr -> nx_ip_routing_table[i].nx_ip_routing_entry_next_hop_address;

            return(NX_SUCCESS);
        }
    }

#endif /* NX_ENABLE_IP_STATIC_ROUTING */


    /* Search through the interfaces associated with the IP instance,
       check whether the entry exists or not. */
    for (i = 0; i < NX_MAX_IP_INTERFACES; i++)
    {

        nx_interface = &(ip_ptr -> nx_ip_interface[i]);

        /* Does the interface network address match the interface network in the IP table? */
        if ((nx_interface -> nx_interface_valid) &&
            ((nx_interface -> nx_interface_ip_network_mask & destination_address) == nx_interface -> nx_interface_ip_network))
        {

            /* Yes it does; Is an interface is supplied by the caller? */
            if (*nx_ip_interface == NX_NULL)
            {

                /* No, so set it here based on matching IP network address. */
                *nx_ip_interface = nx_interface;
            }

            *next_hop_address = destination_address;
            return(NX_SUCCESS);
        }
    }

    /* Match loopback interface, if loopback is enabled. */
#ifndef NX_DISABLE_LOOPBACK_INTERFACE
    if (destination_address == IP_ADDRESS(127, 0, 0, 1))
    {
        *nx_ip_interface = &(ip_ptr -> nx_ip_interface[NX_LOOPBACK_INTERFACE]);
        *next_hop_address = IP_ADDRESS(127, 0, 0, 1);

        return(NX_SUCCESS);
    }

#endif /* !NX_DISABLE_LOOPBACK_INTERFACE */

    /* The destination is not directly attached to one of the local interfaces.
       Use the default gateway. */

    if ((ip_ptr -> nx_ip_gateway_address) && (ip_ptr -> nx_ip_gateway_interface))
    {
        *next_hop_address = ip_ptr -> nx_ip_gateway_address;
        *nx_ip_interface = ip_ptr -> nx_ip_gateway_interface;

        return(NX_SUCCESS);
    }

    /* Cannot find a proper way to transmit this packet.
       Report failure. */

    return(NX_IP_ADDRESS_ERROR);
}

