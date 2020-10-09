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
/**   User Datagram Protocol (UDP)                                        */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_udp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_udp_packet_info_extract                         PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function extracts the source IP, protocol, (the protocol is    */
/*    always UDP), port number and the incoming interface from the        */
/*    incoming packet.                                                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer to UDP packet         */
/*    ip_address                            Pointer to sender IP address  */
/*    protocol                              Pointer to packet protocol.   */
/*                                             Always 17 (UDP)            */
/*    port                                  Pointer to sender source port */
/*    interface_index                       Pointer to interface index    */
/*                                             packet received on         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                           Successful completion status   */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
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
UINT  _nx_udp_packet_info_extract(NX_PACKET *packet_ptr, ULONG *ip_address,
                                  UINT *protocol, UINT *port, UINT *interface_index)
{

ULONG        *temp_ptr;
NX_IP        *ip_ptr;
NX_INTERFACE *nx_interface;
UINT          index;
UINT          source_port;
ULONG         source_ip;


    /* Build an address to the current top of the packet.  */
    temp_ptr =  (ULONG *)packet_ptr -> nx_packet_prepend_ptr;

    /* Pickup the source port.  */
    source_port = (UINT)(*(temp_ptr - 2) >> NX_SHIFT_BY_16);
    if (port != NX_NULL)
    {
        *port = source_port;
    }

    /* Pickup the source IP address.  */
    source_ip = *(temp_ptr - 4);
    if (ip_address != NX_NULL)
    {
        *ip_address = source_ip;
    }

    if (protocol != NX_NULL)
    {
        *protocol = 0x11;
    }

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_UDP_SOURCE_EXTRACT, packet_ptr, source_ip, source_port, 0, NX_TRACE_PACKET_EVENTS, 0, 0);


    if (interface_index == NX_NULL)
    {
        return(NX_SUCCESS);
    }

    /* Search for interface index number.  Initialize interface value as
       invalid (0xFFFFFFFF).  Once we find valid interface, we will update
       the returned value. */
    *interface_index = 0xFFFFFFFF;

    nx_interface = packet_ptr -> nx_packet_ip_interface;

    if (nx_interface == NX_NULL)
    {
        /* No interface attached.  Done here, and return success. */
        return(NX_SUCCESS);
    }

    ip_ptr = nx_interface -> nx_interface_ip_instance;

    /* Find the index number of this interface. */
    for (index = 0; index < NX_MAX_PHYSICAL_INTERFACES; index++)
    {
        if (nx_interface == &(ip_ptr -> nx_ip_interface[index]))
        {
            *interface_index = index;
            break;
        }
    }

    return(NX_SUCCESS);
}

