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
/*    _nx_tcp_socket_state_fin_wait2                      PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes packets during the FIN WAIT 2 state,        */
/*    which is the state after the initial FIN was issued and the other   */
/*    side of the connection issued an ACK.  If a FIN is received in      */
/*    this state, an ACK is sent back the disconnection is complete.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to owning socket      */
/*    tcp_header_ptr                        Pointer to packet header      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_packet_send_ack               Send ACK message              */
/*    _nx_tcp_socket_thread_resume          Resume suspended thread       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_socket_packet_process         Process TCP packet for socket */
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
VOID  _nx_tcp_socket_state_fin_wait2(NX_TCP_SOCKET *socket_ptr, NX_TCP_HEADER *tcp_header_ptr)
{

    /* Determine if the incoming message is a FIN message signalling that the other
       side of the connection is now ready disconnecting as well.  */
    if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT)
    {

        /* Return to the proper socket state.  */

        /* Is this a client socket? */
        if (socket_ptr -> nx_tcp_socket_client_type)
        {

            /* Yes, return the socket to the CLOSED state. */

            /* If trace is enabled, insert this event into the trace buffer.  */
            NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_STATE_CHANGE, socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, socket_ptr -> nx_tcp_socket_state, NX_TCP_CLOSED, NX_TRACE_INTERNAL_EVENTS, 0, 0)

            /* Set the socket state to CLOSED now.  */
            socket_ptr -> nx_tcp_socket_state =  NX_TCP_CLOSED;
        }
        else
        {

            /* No this is a server socket. */

            /* If trace is enabled, insert this event into the trace buffer.  */
            NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_STATE_CHANGE, socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, socket_ptr -> nx_tcp_socket_state, NX_TCP_LISTEN_STATE, NX_TRACE_INTERNAL_EVENTS, 0, 0)

            /* Set the socket state to LISTEN now.  */
            socket_ptr -> nx_tcp_socket_state =  NX_TCP_LISTEN_STATE;
        }

        /* This socket should not have an active timeout. */
        socket_ptr -> nx_tcp_socket_timeout = 0;

        /* Send ACK back to the other side of the connection.  */

        /* Increment the received sequence number.  */
        socket_ptr -> nx_tcp_socket_rx_sequence++;

        /* Send ACK message.  */
        _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);

        /* Determine if we need to wake a thread suspended on the connection.  */
        if (socket_ptr -> nx_tcp_socket_disconnect_suspended_thread)
        {

            /* Resume the thread suspended for the disconnect.  */
            _nx_tcp_socket_thread_resume(&(socket_ptr -> nx_tcp_socket_disconnect_suspended_thread), NX_SUCCESS);
        }


#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT

        /* Is a timed wait callback registered for this socket?  */
        if (socket_ptr -> nx_tcp_timed_wait_callback)
        {

            /* Call the timed wait callback for this socket to let the host
               know the socket can now be put in the timed wait state (if
               the RE-USE ADDRESS socket option is not enabled). */
            (socket_ptr -> nx_tcp_timed_wait_callback)(socket_ptr);

            return;
        }

        /* Is a disconnect complete callback registered with the TCP socket? */
        if (socket_ptr -> nx_tcp_disconnect_complete_notify)
        {

            /* Call the application's disconnect_complete callback function.    */
            (socket_ptr -> nx_tcp_disconnect_complete_notify)(socket_ptr);
        }
#endif
    }
}

