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
#include "nx_packet.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_arp_announce_send                               PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function builds an ARP Announce packet and calls the associated*/
/*    driver to send it out on the specified network interface.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP instance        */
/*    interface_index                       IP Interface Index            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                            Successful completion status  */
/*    NX_NO_PACKET                          No packet available to send   */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_allocate                   Allocate a packet for the     */
/*                                            ARP Announce                */
/*    [ip_link_driver]                      User supplied link driver     */
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
UINT  _nx_arp_announce_send(NX_IP *ip_ptr, UINT interface_index)
{

NX_INTERFACE *nx_interface;
NX_PACKET    *request_ptr;
ULONG        *message_ptr;
NX_IP_DRIVER  driver_request;


    /* Allocate a packet to build the ARP Announce message in.  */
    if (_nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &request_ptr, (NX_PHYSICAL_HEADER + NX_ARP_MESSAGE_SIZE), NX_NO_WAIT))
    {

        /* Error getting packet, so just get out!  */
        return(NX_NO_PACKET);
    }

    /* Get mutex protection.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Set nx_interface.  */
    nx_interface = &(ip_ptr -> nx_ip_interface[interface_index]);

    /* Stamp the packet with the outgoing interface information. */
    request_ptr -> nx_packet_ip_interface = nx_interface;

#ifndef NX_DISABLE_ARP_INFO
    /* Increment the ARP requests sent count.  */
    ip_ptr -> nx_ip_arp_requests_sent++;
#endif

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_ARP_REQUEST_SEND, ip_ptr, nx_interface -> nx_interface_ip_address, request_ptr, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0);

    /* Build the ARP Announce packet.  */

    /* Setup the size of the ARP message.  */
    request_ptr -> nx_packet_length =  NX_ARP_MESSAGE_SIZE;

    /* Setup the prepend pointer.  */
    request_ptr -> nx_packet_prepend_ptr -= NX_ARP_MESSAGE_SIZE;

    /* Setup the pointer to the message area.  */
    message_ptr =  (ULONG *)request_ptr -> nx_packet_prepend_ptr;

    /* Write the Hardware type into the message.  */
    *message_ptr =        (ULONG)(NX_ARP_HARDWARE_TYPE << 16) | (NX_ARP_PROTOCOL_TYPE);
    *(message_ptr + 1) =  (ULONG)(NX_ARP_HARDWARE_SIZE << 24) | (NX_ARP_PROTOCOL_SIZE << 16) |
                                 NX_ARP_OPTION_REQUEST;
    *(message_ptr + 2) =  (ULONG)(nx_interface -> nx_interface_physical_address_msw << 16) |
                                 (nx_interface -> nx_interface_physical_address_lsw >> 16);
    *(message_ptr + 3) =  (ULONG)(nx_interface -> nx_interface_physical_address_lsw << 16) |
                                 (nx_interface -> nx_interface_ip_address >> 16);
    *(message_ptr + 4) =  (ULONG)(nx_interface -> nx_interface_ip_address << 16);
    *(message_ptr + 5) =  (ULONG)0;
    *(message_ptr + 6) =  (ULONG)nx_interface -> nx_interface_ip_address;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 1));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 2));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 3));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 4));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 5));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 6));

    /* Set up the driver request. */
    driver_request.nx_ip_driver_ptr =                   ip_ptr;
    driver_request.nx_ip_driver_command =               NX_LINK_ARP_SEND;
    driver_request.nx_ip_driver_packet =                request_ptr;
    driver_request.nx_ip_driver_physical_address_msw =  0xFFFFUL;
    driver_request.nx_ip_driver_physical_address_lsw =  0xFFFFFFFFUL;
    driver_request.nx_ip_driver_interface            =  nx_interface;

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_ARP_SEND, ip_ptr, request_ptr, request_ptr -> nx_packet_length, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0);

    /* Send the ARP Announce packet to the driver.  */
    (nx_interface -> nx_interface_link_driver_entry)(&driver_request);

    /* Release mutex protection.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Return a successful completion.  */
    return(NX_SUCCESS);
}

