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

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ip.h"
#include "nx_tcp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_connection_reset                     PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes a reset (RST) request received from the     */
/*    other side of the connection.                                       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to socket             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_socket_transmit_queue_flush   Release transmitted packets   */
/*    _nx_tcp_socket_receive_queue_flush    Release received packets      */
/*    _nx_tcp_connect_cleanup               Resume thread suspended       */
/*                                            waiting for connection      */
/*    _nx_tcp_disconnect_cleanup            Resume thread suspended       */
/*                                            waiting for disconnection   */
/*    _nx_tcp_receive_cleanup               Resume threads suspended on   */
/*                                            the receive queue           */
/*    _nx_tcp_transmit_cleanup              Resume threads suspended on   */
/*                                            the transmit queue          */
/*    (application disconnect callback)                                   */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_fast_periodic_processing      Transmit retry timeout        */
/*    _nx_tcp_periodic_processing           Keepalive processing          */
/*    _nx_tcp_socket_packet_process         Socket packet processing      */
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
VOID  _nx_tcp_socket_connection_reset(NX_TCP_SOCKET *socket_ptr)
{

UINT saved_state;

    /* Save the current state of the socket.  */
    saved_state =  socket_ptr -> nx_tcp_socket_state;

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_STATE_CHANGE, socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, socket_ptr -> nx_tcp_socket_state, NX_TCP_CLOSED, NX_TRACE_INTERNAL_EVENTS, 0, 0)

    /* The reset bit is set, immediately enter a CLOSED state.  */
    socket_ptr -> nx_tcp_socket_state =  NX_TCP_CLOSED;

    /* Clear the timeout.  */
    socket_ptr -> nx_tcp_socket_timeout =  0;

    /* Clear the connected IP information to enable new connections
       to come in prior to this socket being unaccepted or unbound.  */
    socket_ptr -> nx_tcp_socket_connect_ip =    0;

    /* Check for queued sent packets and if found they need
       to be released.  */
    if (socket_ptr -> nx_tcp_socket_transmit_sent_count)
    {

        /* Release all transmit packets.  */
        _nx_tcp_socket_transmit_queue_flush(socket_ptr);
    }

    /* Check for queued receive packets and if found they need
       to be released.  */
    if (socket_ptr -> nx_tcp_socket_receive_queue_count)
    {

        /* Release all received packets.  */
        _nx_tcp_socket_receive_queue_flush(socket_ptr);
    }

    /* Clear all receive thread suspensions on this socket.  */
    while (socket_ptr -> nx_tcp_socket_receive_suspension_list)
    {

        /* Call the receive thread suspension cleanup routine.  */
        _nx_tcp_receive_cleanup(socket_ptr -> nx_tcp_socket_receive_suspension_list NX_CLEANUP_ARGUMENT);
    }

    /* Clear all transmit thread suspensions on this socket.  */
    while (socket_ptr -> nx_tcp_socket_transmit_suspension_list)
    {

        /* Call the receive thread suspension cleanup routine.  */
        _nx_tcp_transmit_cleanup(socket_ptr -> nx_tcp_socket_transmit_suspension_list NX_CLEANUP_ARGUMENT);
    }

    /* Check for suspended connect thread.  */
    if (socket_ptr -> nx_tcp_socket_connect_suspended_thread)
    {

        /* Call the connect thread suspension cleanup routine.  */
        _nx_tcp_connect_cleanup(socket_ptr -> nx_tcp_socket_connect_suspended_thread NX_CLEANUP_ARGUMENT);
    }

    /* Check for suspended disconnect thread.  */
    if (socket_ptr -> nx_tcp_socket_disconnect_suspended_thread)
    {

        /* Resume the thread suspended on the disconnect.  */
        _nx_tcp_disconnect_cleanup(socket_ptr -> nx_tcp_socket_disconnect_suspended_thread NX_CLEANUP_ARGUMENT);
    }

    /* Determine if the socket was in an established state.  */
    if (saved_state == NX_TCP_ESTABLISHED)
    {

        /* If given, call the application's disconnect callback function
           for disconnect.  */
        if (socket_ptr -> nx_tcp_disconnect_callback)
        {

            /* Call the application's disconnect handling function.  It is
               responsible for calling the socket disconnect function.  */
            (socket_ptr -> nx_tcp_disconnect_callback)(socket_ptr);
        }
    }

#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT

    /* Is a disconnect complete callback registered with the TCP socket? */
    if (socket_ptr -> nx_tcp_disconnect_complete_notify)
    {

        /* Notify the application through the socket disconnect_complete callback.  */
        (socket_ptr -> nx_tcp_disconnect_complete_notify)(socket_ptr);
    }
#endif
}

