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
#include "nx_packet.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_bytes_available                      PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function determines the number of bytes available on a TCP     */
/*    socket for reception.                                               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to the TCP socket     */
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
UINT  _nx_tcp_socket_bytes_available(NX_TCP_SOCKET *socket_ptr, ULONG *bytes_available)
{

NX_IP         *ip_ptr;
NX_PACKET     *packet_ptr;
ULONG          data_size;
NX_TCP_HEADER *header_ptr;
ULONG          header_length;
INT            done = 0;


    /* Setup IP pointer. */
    ip_ptr = socket_ptr -> nx_tcp_socket_ip_ptr;

    /* Obtain the IP mutex so we can examine the bound port.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Initialize the result of the byte count to zero. */
    *bytes_available = 0;

    /* Make sure the TCP connection has been established. */
    if ((socket_ptr -> nx_tcp_socket_state <= NX_TCP_LISTEN_STATE) ||
        (socket_ptr -> nx_tcp_socket_state > NX_TCP_ESTABLISHED))
    {

        /* Release protection.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        return(NX_NOT_CONNECTED);
    }

    /* Get a pointer to the start of the packet receive queue. */
    packet_ptr = socket_ptr -> nx_tcp_socket_receive_queue_head;

    /* Is there anything in the queue? */
    if (packet_ptr == NX_NULL)
    {

        /* No; receive queue is empty. */

        /* Release protection.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        /* We're done.*/
        return(NX_SUCCESS);
    }

    /* Loop through all the packets on the queue and find out the total
       number of bytes in the receive queue available to the application. */
    do
    {

        data_size = 0;

        /* Make sure the packet is ready to be received. */
        if (packet_ptr -> nx_packet_queue_next == ((NX_PACKET *)NX_PACKET_READY))
        {

            /* Compute the size of TCP payload in this packet */
            header_ptr =  (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

            /* Calculate the header size for this packet.  */
            header_length = ((header_ptr -> nx_tcp_header_word_3 >> NX_TCP_HEADER_SHIFT) * sizeof(ULONG));

            /* Do not include header size as bytes available. */
            data_size = (packet_ptr -> nx_packet_length - header_length);

            *bytes_available += data_size;

            /* Is this the last packet? */
            if (packet_ptr == socket_ptr -> nx_tcp_socket_receive_queue_tail)
            {

                /* Yes; Already reached the last packet.  */
                done = 1;
            }
            else
            {

                /* Move on to the next packet. */
                packet_ptr = packet_ptr -> nx_packet_tcp_queue_next;
            }
        }
        else
        {

            /* If the packet has not been acked yet, then just return the
               amount of bytes available so far. */
            done = 1;
        }
    } while (!done);

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_TCP_SOCKET_BYTES_AVAILABLE, ip_ptr, socket_ptr, *bytes_available, 0, NX_TRACE_UDP_EVENTS, 0, 0);

    /* Release protection.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_SUCCESS);
}

