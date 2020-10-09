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
/*    _nx_udp_socket_extract                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function extracts the source IP and UDP port number from the   */
/*    supplied packet.  If the supplied packet does not have an IP and    */
/*    UDP header, an error will be returned.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer to UDP packet pointer */
/*    ip_address                            Pointer to destination for IP */
/*                                            address                     */
/*    port                                  Pointer to destination for    */
/*                                            source UDP port             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
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
UINT  _nx_udp_source_extract(NX_PACKET *packet_ptr, ULONG *ip_address, UINT *port)
{

ULONG *temp_ptr;


    /* Build an address to the current top of the packet.  */
    temp_ptr =  (ULONG *)packet_ptr -> nx_packet_prepend_ptr;

    /* Pickup the source port.  */
    *port =  (UINT)(*(temp_ptr - 2) >> NX_SHIFT_BY_16);

    /* Pickup the source IP address.  */
    *ip_address =  *(temp_ptr - 4);

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_UDP_SOURCE_EXTRACT, packet_ptr, *ip_address, *port, 0, NX_TRACE_UDP_EVENTS, 0, 0)

    /* Determine if IP address is non-zero.  */
    if (*ip_address)
    {

        /* Return a successful status to the caller.  */
        return(NX_SUCCESS);
    }
    else
    {

        /* Return an invalid packet error.  */
        return(NX_INVALID_PACKET);
    }
}

