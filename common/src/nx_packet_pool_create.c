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
/*    _nx_packet_pool_create                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates a pool of fixed-size packets within the       */
/*    specified memory area.                                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    pool_ptr                              Packet Pool control block     */
/*    name_ptr                              Packet Pool string pointer    */
/*    payload_size                          Size of packet payload        */
/*    pool_start                            Starting address of pool      */
/*    pool_size                             Number of bytes in pool       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Return status                 */
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
UINT  _nx_packet_pool_create(NX_PACKET_POOL *pool_ptr, CHAR *name_ptr, ULONG payload_size,
                             VOID *pool_start, ULONG pool_size)
{

TX_INTERRUPT_SAVE_AREA

NX_PACKET_POOL *tail_ptr;               /* Working packet pool pointer */
ULONG           packets;                /* Number of packets in pool   */
ULONG           original_payload_size;  /* Original payload size       */
CHAR           *packet_ptr;             /* Working packet pointer      */
CHAR           *next_packet_ptr;        /* Next packet pointer         */
CHAR           *end_of_pool;            /* End of pool area            */


    /* Save the original payload size.  */
    original_payload_size =  payload_size;

    /* Round the packet size up to something that is evenly divisible by
       an ULONG.  This helps guarantee proper alignment.  */
    payload_size =  ((payload_size + sizeof(ULONG) - 1) / sizeof(ULONG)) * sizeof(ULONG);

    /* Round the pool size down to something that is evenly divisible by
       an ULONG.  */
    pool_size =   (pool_size / sizeof(ULONG)) * sizeof(ULONG);

    /* Setup the basic packet pool fields.  */
    pool_ptr -> nx_packet_pool_name =             name_ptr;
    pool_ptr -> nx_packet_pool_suspension_list =  TX_NULL;
    pool_ptr -> nx_packet_pool_suspended_count =  0;
    pool_ptr -> nx_packet_pool_start =            (CHAR *)pool_start;
    pool_ptr -> nx_packet_pool_size =             pool_size;
    pool_ptr -> nx_packet_pool_payload_size =     original_payload_size;

    /* Calculate the end of the pool's memory area.  */
    end_of_pool =  ((CHAR *)pool_start) + pool_size;

    /* Walk through the pool area, setting up the available packet list.  */
    packets =            0;
    packet_ptr =         (CHAR *)pool_start;
    next_packet_ptr =    packet_ptr + (payload_size + sizeof(NX_PACKET));
    while (next_packet_ptr <= end_of_pool)
    {

        /* Yes, we have another packet.  Increment the packet count.  */
        packets++;

        /* Setup the link to the next packet.  */
        ((NX_PACKET *)packet_ptr) -> nx_packet_next =  (NX_PACKET *)next_packet_ptr;

        /* Remember that this packet pool is the owner.  */
        ((NX_PACKET *)packet_ptr) -> nx_packet_pool_owner =  pool_ptr;

        /* Clear the next packet pointer.  */
        ((NX_PACKET *)packet_ptr) -> nx_packet_queue_next =  (NX_PACKET *)NX_NULL;

        /* Mark the packet as free.  */
        ((NX_PACKET *)packet_ptr) -> nx_packet_tcp_queue_next =  (NX_PACKET *)NX_PACKET_FREE;

        /* Setup the packet data pointers.  */
        ((NX_PACKET *)packet_ptr) -> nx_packet_data_start =  (UCHAR *)(packet_ptr + sizeof(NX_PACKET));
        ((NX_PACKET *)packet_ptr) -> nx_packet_data_end =    (UCHAR *)(packet_ptr + sizeof(NX_PACKET) + original_payload_size);

        /* Advance to the next packet.  */
        packet_ptr =   next_packet_ptr;

        /* Update the next packet pointer.  */
        next_packet_ptr =  packet_ptr + (payload_size + sizeof(NX_PACKET));
    }

    /* Backup to the last packet in the pool.  */
    packet_ptr =  packet_ptr - (payload_size + sizeof(NX_PACKET));

    /* Set the last packet's forward pointer to NULL.  */
    ((NX_PACKET *)packet_ptr) -> nx_packet_next =  NX_NULL;

    /* Save the remaining information in the pool control packet.  */
    pool_ptr -> nx_packet_pool_available =  packets;
    pool_ptr -> nx_packet_pool_total =      packets;

    /* Quickly check to make sure at least one packet is in the pool.  */
    if (packets)
    {
        pool_ptr -> nx_packet_pool_available_list =  (NX_PACKET *)pool_start;
    }
    else
    {
        pool_ptr -> nx_packet_pool_available_list =  TX_NULL;
    }

    /* If trace is enabled, register this object.  */
    NX_TRACE_OBJECT_REGISTER(NX_TRACE_OBJECT_TYPE_PACKET_POOL, pool_ptr, name_ptr, payload_size, packets)

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_PACKET_POOL_CREATE, pool_ptr, payload_size, pool_start, pool_size, NX_TRACE_PACKET_EVENTS, 0, 0)

    /* Disable interrupts to place the packet pool on the created list.  */
    TX_DISABLE

    /* Setup the packet pool ID to make it valid.  */
    pool_ptr -> nx_packet_pool_id =  NX_PACKET_POOL_ID;

    /* Place the packet pool on the list of created packet pools.  First,
       check for an empty list.  */
    if (_nx_packet_pool_created_ptr)
    {

        /* Pickup tail pointer.  */
        tail_ptr =  _nx_packet_pool_created_ptr -> nx_packet_pool_created_previous;

        /* Place the new packet pool in the list.  */
        _nx_packet_pool_created_ptr -> nx_packet_pool_created_previous =  pool_ptr;
        tail_ptr -> nx_packet_pool_created_next =  pool_ptr;

        /* Setup this packet pool's created links.  */
        pool_ptr -> nx_packet_pool_created_previous =  tail_ptr;
        pool_ptr -> nx_packet_pool_created_next =      _nx_packet_pool_created_ptr;
    }
    else
    {

        /* The created packet pool list is empty.  Add packet pool to empty list.  */
        _nx_packet_pool_created_ptr =                  pool_ptr;
        pool_ptr -> nx_packet_pool_created_next =      pool_ptr;
        pool_ptr -> nx_packet_pool_created_previous =  pool_ptr;
    }

    /* Increment the number of packet pools created.  */
    _nx_packet_pool_created_count++;

    /* Restore interrupts.  */
    TX_RESTORE

    /* Return NX_SUCCESS.  */
    return(NX_SUCCESS);
}

