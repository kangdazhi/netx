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

#ifndef NX_SOURCE_CODE
#define NX_SOURCE_CODE
#endif


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_udp.h"



/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_udp_socket_bytes_available                      PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function determines the number of bytes available on a UDP     */
/*    socket for reception.                                               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to the UDP sockete    */
/*    bytes_available                       Number of bytes returned to   */
/*                                             the caller.                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Obtain protection             */
/*    tx_mutex_put                          Release protection            */
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
UINT  _nx_udp_socket_bytes_available(NX_UDP_SOCKET *socket_ptr, ULONG *bytes_available)
{

NX_IP     *ip_ptr;
NX_PACKET *packet_ptr;
ULONG      count;


    /* Setup IP pointer. */
    ip_ptr = socket_ptr -> nx_udp_socket_ip_ptr;

    /* Obtain the IP mutex so we can examine the bound port.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    *bytes_available = 0;

    /* Determine if the socket is currently bound. */
    if (!socket_ptr -> nx_udp_socket_bound_next)
    {
        /* Release mutex */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        return(NX_NOT_SUCCESSFUL);
    }

    packet_ptr = socket_ptr -> nx_udp_socket_receive_head;

    /* Loop through all the packets on the queue and find out the total
       number of bytes in the rx queue that are available to the applciation. */
    for (count = 0; count < socket_ptr -> nx_udp_socket_receive_count; count++)
    {

        *bytes_available += (packet_ptr -> nx_packet_length - sizeof(NX_UDP_HEADER));

        /* Move on to the next packet. */
        packet_ptr = packet_ptr -> nx_packet_queue_next;
    }

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_UDP_SOCKET_BYTES_AVAILABLE, ip_ptr, socket_ptr, *bytes_available, 0, NX_TRACE_UDP_EVENTS, 0, 0);

    /* Release protection.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_SUCCESS);
}

