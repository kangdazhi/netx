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
/*    _nx_packet_data_retrieve                            PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function copies data from a NetX packet (or packet chain) into */
/*    the supplied user buffer.                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer to the source packet  */
/*    buffer_start                          Pointer to destination area   */
/*    bytes_copied                          Number of bytes copied        */
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
UINT  _nx_packet_data_retrieve(NX_PACKET *packet_ptr, VOID *buffer_start, ULONG *bytes_copied)
{

ULONG  remaining_bytes;
UCHAR *source_ptr;
UCHAR *destination_ptr;


    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_PACKET_DATA_RETRIEVE, packet_ptr, buffer_start, bytes_copied, 0, NX_TRACE_PACKET_EVENTS, 0, 0)

    /* Setup the destination pointer.  */
    destination_ptr =  buffer_start;

    /* Pickup the amount of bytes to copy.  */
    *bytes_copied =  packet_ptr -> nx_packet_length;

    /* Setup the remaining bytes.  */
    remaining_bytes =  packet_ptr -> nx_packet_length;

    /* Loop to copy bytes from packet(s).  */
    while (packet_ptr)
    {

        /* Setup loop to copy from this packet.  */
        source_ptr =  packet_ptr -> nx_packet_prepend_ptr;

        /* Copy bytes from this packet.  */
        while (remaining_bytes)
        {

            /* Determine if we are at the end of the packet's buffer.  */
            if (source_ptr == packet_ptr -> nx_packet_append_ptr)
            {

                /* Yes, get out of this inner loop.  */
                break;
            }

            /* Copy byte and increment both pointers.  */
            *destination_ptr++ = *source_ptr++;

            /* Decrement the remaining bytes to copy. */
            remaining_bytes--;
        }

        /* Move to next packet.  */
        packet_ptr =  packet_ptr -> nx_packet_next;
    }

    /* Determine if the packet chain was valid.  */
    if (remaining_bytes)
    {

        /* Invalid packet chain.  Calculate the actual number of bytes
           copied.  */
        *bytes_copied =  *bytes_copied - remaining_bytes;

        /* Return an error.  */
        return(NX_INVALID_PACKET);
    }

    /* Return successful completion.  */
    return(NX_SUCCESS);
}

