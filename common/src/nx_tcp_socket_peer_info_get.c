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
/**   Transmission Control Protocol (TCP)                                 */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#ifndef NX_SOURCE_CODE
#define NX_SOURCE_CODE
#endif


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_tcp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_peer_info_get                        PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function retrieves IP address and port number of the peer      */
/*    connected to the specified TCP socket.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to the TCP sockete    */
/*    peer_ip_address                       Pointer to the IP address     */
/*                                             of the peer.               */
/*    peer_port                             Pointer to the port number    */
/*                                             of the peer.               */
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
UINT  _nx_tcp_socket_peer_info_get(NX_TCP_SOCKET *socket_ptr,
                                   ULONG *peer_ip_address,
                                   ULONG *peer_port)
{
NX_IP *ip_ptr;

    /* Setup IP pointer. */
    ip_ptr = socket_ptr -> nx_tcp_socket_ip_ptr;

    /* Obtain the IP mutex so we can examine the bound port.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);


    /* Make sure the TCP connection has been established. */
    if ((socket_ptr -> nx_tcp_socket_state <= NX_TCP_LISTEN_STATE) ||
        (socket_ptr -> nx_tcp_socket_state > NX_TCP_ESTABLISHED))
    {
        /* Release protection.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        return(NX_NOT_CONNECTED);
    }

    /* Determine the peer IP address */
    if (peer_ip_address)
    {
        /* Return the IP address of the peer connected to the TCP socket. */
        *peer_ip_address = socket_ptr -> nx_tcp_socket_connect_ip;
    }


    /* Determine the peer port number */
    if (peer_port)
    {
        /* Return the port number of the peer connected to the TCP socket. */
        *peer_port = socket_ptr -> nx_tcp_socket_connect_port;
    }

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_TCP_SOCKET_PEER_INFO_GET, socket_ptr, *peer_ip_address, *peer_port, 0, NX_TRACE_TCP_EVENTS, 0, 0)


    /* Release protection.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Return successful completion status.  */
    return(NX_SUCCESS);
}

