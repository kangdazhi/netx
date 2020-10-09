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
/**   Packet Pool Management (Packet)                                     */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_packet.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_packet_copy                                     PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function copies the specified packet into one or more packets  */
/*    allocated from the specified packet pool.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer to source packet      */
/*    new_packet_ptr                        Pointer for return packet     */
/*    pool_ptr                              Pointer to packet pool to use */
/*                                            for new packet(s)           */
/*    wait_option                           Suspension option             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_allocate                   Allocate data packet          */
/*    _nx_packet_data_append                Packet data append service    */
/*    _nx_packet_release                    Release data packet           */
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
UINT  _nx_packet_copy(NX_PACKET *packet_ptr, NX_PACKET **new_packet_ptr,
                      NX_PACKET_POOL *pool_ptr, ULONG wait_option)
{

NX_PACKET *work_ptr;                    /* Working packet pointer     */
NX_PACKET *source_ptr;                  /* Source packet pointer      */
ULONG      size;                        /* Packet data size           */
UINT       status;                      /* Return status              */

#ifdef TX_ENABLE_EVENT_TRACE
TX_TRACE_BUFFER_ENTRY *trace_event;
ULONG                  trace_timestamp;
#endif


    /* Default the return packet pointer to NULL.  */
    *new_packet_ptr =  NX_NULL;

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_PACKET_COPY, packet_ptr, 0, pool_ptr, wait_option, NX_TRACE_PACKET_EVENTS, &trace_event, &trace_timestamp)

    /* Determine if there is anything to copy.  */
    if (!packet_ptr -> nx_packet_length)
    {

        /* Empty source packet, return an error.  */
        return(NX_INVALID_PACKET);
    }

    /* Allocate a new packet from the default packet pool supplied.  */
    status =  _nx_packet_allocate(pool_ptr, &work_ptr,
                                  (ULONG)(packet_ptr -> nx_packet_prepend_ptr - packet_ptr -> nx_packet_data_start), wait_option);

    /* Determine if the packet was not allocated.  */
    if (status != NX_SUCCESS)
    {

        /* Return the error code from the packet allocate routine.  */
        return(status);
    }

    /* Copy the packet interface information. */
    work_ptr -> nx_packet_ip_interface = packet_ptr -> nx_packet_ip_interface;

    /* Copy the packet next hop address */
    work_ptr -> nx_packet_next_hop_address = packet_ptr -> nx_packet_next_hop_address;

    /* Save the source packet pointer.  */
    source_ptr =  packet_ptr;

    /* Loop to copy the original packet's data.  */
    do
    {

        /* Calculate this packet's data size.  */
        size =  (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);

        /* Copy the data from the source packet into the new packet using
           the data append feature.  */
        status =  _nx_packet_data_append(work_ptr, packet_ptr -> nx_packet_prepend_ptr, size, pool_ptr, wait_option);

        /* Determine if there was an error in the data append.  */
        if (status != NX_SUCCESS)
        {

            /* An error is present, release the new packet.  */
            _nx_packet_release(work_ptr);

            /* Return the error code from the packet data append service.  */
            return(status);
        }

        /* Move to the next packet in the packet chain.  */
        packet_ptr =  packet_ptr -> nx_packet_next;
    } while (packet_ptr);

    /* Determine if the packet copy was successful.  */
    if (source_ptr -> nx_packet_length != work_ptr -> nx_packet_length)
    {

        /* An error is present, release the new packet.  */
        _nx_packet_release(work_ptr);

        /* Return an error code.  */
        return(NX_INVALID_PACKET);
    }
    else
    {

        /* Everything is okay, return the new packet pointer.  */
        *new_packet_ptr =  work_ptr;

        /* Update the trace event with the status.  */
        NX_TRACE_EVENT_UPDATE(trace_event, trace_timestamp, NX_TRACE_PACKET_COPY, 0, work_ptr, 0, 0)

        /* Return success status.  */
        return(NX_SUCCESS);
    }
}

