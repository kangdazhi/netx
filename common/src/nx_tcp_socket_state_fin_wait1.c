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
/*    _nx_tcp_socket_state_fin_wait1                      PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes packets during the FIN WAIT 1 state,        */
/*    which is the state after the initial FIN was issued in an active    */
/*    disconnect issued by the application.                               */
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
VOID  _nx_tcp_socket_state_fin_wait1(NX_TCP_SOCKET *socket_ptr, NX_TCP_HEADER *tcp_header_ptr)
{


    /* Determine if the incoming message is an ACK only message.  If it is and
       if it is proper, move into the FIN WAIT 2 state and do nothing else.  */
    if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) &&
        (tcp_header_ptr -> nx_tcp_acknowledgment_number == socket_ptr -> nx_tcp_socket_tx_sequence) &&
        (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT)))
    {

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_STATE_CHANGE, socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, socket_ptr -> nx_tcp_socket_state, NX_TCP_FIN_WAIT_2, NX_TRACE_INTERNAL_EVENTS, 0, 0)

        /* We have a legitimate ACK message.  Simply move into the WAIT FIN 2 state
           for the other side to finish its processing and disconnect.  */
        socket_ptr -> nx_tcp_socket_state =  NX_TCP_FIN_WAIT_2;

        /* Otherwise, simply clear the FIN timeout.  */
        socket_ptr -> nx_tcp_socket_timeout =  0;
    }
    else if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) &&
             (tcp_header_ptr -> nx_tcp_acknowledgment_number == socket_ptr -> nx_tcp_socket_tx_sequence) &&
             (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT))
    {

        /* Is this a client socket?.  */
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

            /* No, this is a server socket. */

            /* If trace is enabled, insert this event into the trace buffer.  */
            NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_STATE_CHANGE, socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, socket_ptr -> nx_tcp_socket_state, NX_TCP_LISTEN_STATE, NX_TRACE_INTERNAL_EVENTS, 0, 0)

            /* Set the socket state to LISTEN directly.  */
            socket_ptr -> nx_tcp_socket_state =  NX_TCP_LISTEN_STATE;
        }

        /* Otherwise, simply clear the FIN timeout.  */
        socket_ptr -> nx_tcp_socket_timeout =  0;

        /* Send ACK back to the other side of the connection.  */

        /* Increment the received sequence.  */
        socket_ptr -> nx_tcp_socket_rx_sequence++;

        /* Send ACK message.  */
        _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);

        /* Determine if we need to wake a thread suspended on the connection.  */
        if (socket_ptr -> nx_tcp_socket_disconnect_suspended_thread)
        {

            /* Resume the thread suspended for the disconnect.  */
            _nx_tcp_socket_thread_resume(&(socket_ptr -> nx_tcp_socket_disconnect_suspended_thread), NX_SUCCESS);
        }
    }
    else if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT)
    {

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_STATE_CHANGE, socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, socket_ptr -> nx_tcp_socket_state, NX_TCP_CLOSING, NX_TRACE_INTERNAL_EVENTS, 0, 0)

        /* Move to the CLOSING state for simultaneous close situation.  */
        socket_ptr -> nx_tcp_socket_state =  NX_TCP_CLOSING;

        /* Send ACK back to the other side of the connection.  */

        /* Increment the received sequence number.  */
        socket_ptr -> nx_tcp_socket_rx_sequence++;

        /* Send ACK message.  */
        _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);
    }

#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT

    /* If the socket connection is shut down, check if we need to notify the host application the
       socket is entering the timed wait state. */
    if ((socket_ptr -> nx_tcp_socket_state ==  NX_TCP_CLOSED) || (socket_ptr -> nx_tcp_socket_state ==  NX_TCP_LISTEN_STATE))
    {


        /* Is a timed wait callback registered for this socket?  This puts the socket
           in a timed wait state but returns immediately rather than block the IP thread entry. */
        if (socket_ptr -> nx_tcp_timed_wait_callback)
        {

            (socket_ptr -> nx_tcp_timed_wait_callback)(socket_ptr);
            return;
        }


        /* If registered with the TCP socket, call the application's disconnect complete function.  */
        if (socket_ptr -> nx_tcp_disconnect_complete_notify)
        {

            /* Call the application's disconnect_complete callback function. */
            (socket_ptr -> nx_tcp_disconnect_complete_notify)(socket_ptr);
        }
    }
#endif
}

