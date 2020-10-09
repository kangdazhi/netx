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
#include "tx_thread.h"
#include "nx_packet.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_packet_release                                  PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function releases the packet chain back to the appropriate     */
/*    packet pools.                                                       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer of packet to release  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _tx_thread_system_resume              Resume suspended thread       */
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
UINT  _nx_packet_release(NX_PACKET *packet_ptr)
{

TX_INTERRUPT_SAVE_AREA

NX_PACKET_POOL *pool_ptr;               /* Pool pointer            */
TX_THREAD      *thread_ptr;             /* Working thread pointer  */
NX_PACKET      *next_packet;            /* Working block pointer   */


    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_PACKET_RELEASE, packet_ptr, packet_ptr -> nx_packet_tcp_queue_next, (packet_ptr -> nx_packet_pool_owner) -> nx_packet_pool_available, 0, NX_TRACE_PACKET_EVENTS, 0, 0)

    /* Loop to free all packets chained together, not assuming they are
       from the same pool.  */
    while (packet_ptr)
    {

        /* Check to see if the packet is releasable.  */
        if (packet_ptr -> nx_packet_tcp_queue_next != ((NX_PACKET *)NX_PACKET_ALLOCATED))
        {

#ifndef NX_DISABLE_PACKET_INFO
            /* Pickup the pool pointer.  */
            pool_ptr =  packet_ptr -> nx_packet_pool_owner;

            /* Check for a good pool pointer...  error must be the packet!  */
            if ((pool_ptr) && (pool_ptr -> nx_packet_pool_id == NX_PACKET_POOL_ID))
            {

                /* Increment the packet pool invalid release error count.  */
                pool_ptr -> nx_packet_pool_invalid_releases++;
            }
#endif

            /* Return an error indicating the packet could not be released.  */
            return(NX_PTR_ERROR);
        }
        /* End of packet check.  */

        /* Pickup the next packet. */
        next_packet =  packet_ptr -> nx_packet_next;

        /* Disable interrupts to put this packet back in the packet pool.  */
        TX_DISABLE

        /* Pickup the pool pointer.  */
        pool_ptr =  packet_ptr -> nx_packet_pool_owner;

        /* Determine if there are any threads suspended on the block pool.  */
        thread_ptr =  pool_ptr -> nx_packet_pool_suspension_list;
        if (thread_ptr)
        {

            /* Remove the suspended thread from the list.  */

            /* See if this is the only suspended thread on the list.  */
            if (thread_ptr == thread_ptr -> tx_thread_suspended_next)
            {

                /* Yes, the only suspended thread.  */

                /* Update the head pointer.  */
                pool_ptr -> nx_packet_pool_suspension_list =  NX_NULL;
            }
            else
            {

                /* At least one more thread is on the same expiration list.  */

                /* Update the list head pointer.  */
                pool_ptr -> nx_packet_pool_suspension_list =  thread_ptr -> tx_thread_suspended_next;

                /* Update the links of the adjacent threads.  */
                (thread_ptr -> tx_thread_suspended_next) -> tx_thread_suspended_previous =
                    thread_ptr -> tx_thread_suspended_previous;
                (thread_ptr -> tx_thread_suspended_previous) -> tx_thread_suspended_next =
                    thread_ptr -> tx_thread_suspended_next;
            }

            /* Decrement the suspension count.  */
            pool_ptr -> nx_packet_pool_suspended_count--;

            /* Prepare for resumption of the first thread.  */

            /* Clear cleanup routine to avoid timeout.  */
            thread_ptr -> tx_thread_suspend_cleanup =  TX_NULL;

            /* Temporarily disable preemption.  */
            _tx_thread_preempt_disable++;

            /* Restore interrupts.  */
            TX_RESTORE

            /* Adjust this packet to look just like a new packet.  */
            packet_ptr -> nx_packet_next =         NX_NULL;
            packet_ptr -> nx_packet_queue_next =   NX_NULL;
            packet_ptr -> nx_packet_last =         NX_NULL;
            packet_ptr -> nx_packet_length =       0;
            packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_data_start + (thread_ptr -> tx_thread_suspend_info);
            packet_ptr -> nx_packet_append_ptr =   packet_ptr -> nx_packet_prepend_ptr;

            /* Return this block pointer to the suspended thread waiting for
               a block.  */
            *((NX_PACKET **)thread_ptr -> tx_thread_additional_suspend_info) =  packet_ptr;

            /* Put return status into the thread control block.  */
            thread_ptr -> tx_thread_suspend_status =  NX_SUCCESS;

            /* Resume thread.  */
            _tx_thread_system_resume(thread_ptr);
        }
        else
        {

            /* No thread is suspended for a memory block.  */

            /* Mark the packet as free.  */
            packet_ptr -> nx_packet_tcp_queue_next =  (NX_PACKET *)NX_PACKET_FREE;

            /* Put the packet back in the available list.  */
            packet_ptr -> nx_packet_next =  pool_ptr -> nx_packet_pool_available_list;

            /* Adjust the head pointer.  */
            pool_ptr -> nx_packet_pool_available_list =  packet_ptr;

            /* Increment the count of available blocks.  */
            pool_ptr -> nx_packet_pool_available++;

            /* Restore interrupts.  */
            TX_RESTORE
        }

        /* Move to the next packet in the list.  */
        packet_ptr =  next_packet;
    }

    /* Return completion status.  */
    return(NX_SUCCESS);
}

