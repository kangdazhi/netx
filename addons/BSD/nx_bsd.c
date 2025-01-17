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
/** BSD 4.3 Socket API Compatible Interface to NetX                       */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/* Include necessary files.  */
#include "nx_api.h"
#include "nx_packet.h"
#include "nx_tcp.h"
#include "nx_ip.h"

#include "nx_bsd.h"

#ifdef NX_BSD_ENABLE_DNS
#include "nx_dns.h"
#endif


#include "nx_udp.h"
#include "nx_igmp.h"
#include "nx_system.h"
#include "tx_timer.h"

/* Define a NetX packet pool pointer for BSD use.  */

NX_PACKET_POOL          *nx_bsd_default_packet_pool;


/* Define the default IP instance for BSD use.   */

NX_IP                   *nx_bsd_default_ip;


/* Define the single mutex protection for the BSD layer calls.  */

TX_MUTEX                *nx_bsd_protection_ptr;


/* Define IP fast periodic timer entry. */
VOID                    (*nx_bsd_ip_fast_periodic_timer_entry)(ULONG id);

/* Define BSD system clock time. The precision depends on _nx_ip_fast_timer_rate. */
ULONG                   nx_bsd_system_clock;

/* Define BSD system clock timer rate. */
ULONG                   nx_bsd_timer_rate;

/* Define the event flag group for notifying threads suspended on BSD sockets to wakeup.  */

TX_EVENT_FLAGS_GROUP    nx_bsd_events;


/* Define the array of BSD managed sockets.  */

NX_BSD_SOCKET           nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];


/* Create some buffer space for number string conversions. */
#define                 NX_BSD_URL_BUFSIZE  18
CHAR                    nx_bsd_url_buffer[NX_BSD_URL_BUFSIZE];

/* Define the search index for the BSD array.  */

UINT                    nx_bsd_socket_array_index;


/* Define the block pool that will be used to dynamically allocate either NetX UDP or TCP sockets.  */

TX_BLOCK_POOL           nx_bsd_socket_block_pool;

/* Define the memory area for the socket block pool... use TCP socket size, since it is the larger.  */

static ULONG            nx_bsd_socket_pool_memory[NX_BSD_MAX_SOCKETS * (sizeof(NX_TCP_SOCKET) + sizeof(VOID *)) / sizeof(ULONG)];

/* Define the block pool that will be used to dynamically allocate addrinfo struct. */

TX_BLOCK_POOL           nx_bsd_addrinfo_block_pool;

/* Define the memory area for addrinfo pool. sizeof(addrinfo) is the MAX of: 
 * {sizeof(addrinfo)== 32, sizeof(sockaddr_in) == 16, or sizeof(sockaddr_in6)} = 28. 
 * Every address may be  mapped to 3 socktypes, SOCK_STREAM and SOCK_DGRAM, 
 * 3 blocks for addrinfo) + 1 block for IP adddress = 4 blocks */
 
static ULONG            nx_bsd_addrinfo_pool_memory[NX_BSD_IPV4_ADDR_MAX_NUM * 4 
                                                    *(sizeof(struct addrinfo) + sizeof(VOID *)) / sizeof(ULONG)];

#ifdef NX_BSD_ENABLE_DNS

/* The global DNS client instance. */
extern NX_DNS *_nx_dns_instance_ptr;

#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
/* Define the block pool that will be used to dynamically allocate canonical name buffer. */
TX_BLOCK_POOL           nx_bsd_cname_block_pool;

/* Here we just support a CNAME per IP address. */                                                   
static ULONG            nx_bsd_cname_pool_memory[NX_BSD_IPV4_ADDR_MAX_NUM * (NX_DNS_NAME_MAX + 1) / sizeof(ULONG)]; 
#endif /* NX_DNS_ENABLE_EXTENDED_RR_TYPES */
#endif /* NX_BSD_ENABLE_DNS */

/* Buffer used to store IP address get from DNS. */
static ULONG           nx_bsd_ipv4_addr_buffer[NX_BSD_IPV4_ADDR_PER_HOST];

/* Utility character type functions*/
static UINT nx_bsd_isspace(UCHAR c);
static UINT nx_bsd_islower(UCHAR c);
static UINT nx_bsd_isdigit(UCHAR c);
static UINT nx_bsd_isxdigit(UCHAR c);

/* Standard BSD callback functions to register with NetX. */

static VOID  nx_bsd_tcp_receive_notify(NX_TCP_SOCKET *socket_ptr);
static VOID  nx_bsd_tcp_socket_disconnect_notify(NX_TCP_SOCKET *socket_ptr);
static VOID  nx_bsd_udp_receive_notify(NX_UDP_SOCKET *socket_ptr);
#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
static VOID  nx_bsd_tcp_establish_notify(NX_TCP_SOCKET *socket_ptr);
#endif /* NX_DISABLE_EXTENDED_NOTIFY_SUPPORT */
static VOID  nx_bsd_select_wakeup(UINT sock_id, UINT fdsets);
static VOID  nx_bsd_set_error_code(NX_BSD_SOCKET *bsd_socket_ptr, UINT status_code);
static VOID  nx_bsd_udp_packet_received(INT sockID, NX_PACKET *packet_ptr);
static UINT  nx_bsd_tcp_syn_received_notify(NX_TCP_SOCKET *socket_ptr, NX_PACKET *packet_ptr);
static INT   nx_bsd_tcp_create_listen_socket(INT master_sockid, INT backlog);
static VOID  nx_bsd_tcp_pending_connection(UINT local_port, NX_TCP_SOCKET *socket_ptr);
static INT   nx_bsd_send_internal(INT sockID, const CHAR *msg, INT msgLength, INT flags,
                                  ULONG dst_address, USHORT dst_port, UINT local_interface_index);


static INT   inet_ntoa_internal(const VOID *src, CHAR *dst, ULONG dst_size);
static INT   bsd_string_to_number(const CHAR *string, UINT *number);
static ULONG _nx_bsd_string_length(CHAR * string);


#ifdef NX_BSD_RAW_SUPPORT
static INT   _nx_bsd_hardware_internal_sendto(NX_BSD_SOCKET *bsd_socket_ptr, CHAR *msg, INT msgLength, 
                                              INT flags,  struct sockaddr* destAddr, INT destAddrLen);
static VOID  _nx_bsd_hardware_packet_received(NX_PACKET *packet_ptr, UCHAR *consumed);
#endif /* NX_BSD_RAW_SUPPORT */
static VOID  _nx_bsd_fast_periodic_timer_entry(ULONG id);

#ifndef NX_BSD_TIMEOUT_PROCESS_IN_TIMER
TX_THREAD               nx_bsd_task_thread;
static VOID             nx_bsd_thread_entry(ULONG info);
#else
static TX_TIMER         nx_bsd_timer;
static VOID             nx_bsd_timer_entry(ULONG info);
#endif
UINT  bsd_number_convert(UINT number, CHAR *string, ULONG buffer_len, UINT base);
VOID  nx_bsd_socket_timed_wait_callback(NX_TCP_SOCKET *tcp_socket_ptr);

#define FDSET_READ       1
#define FDSET_WRITE      2
#define FDSET_EXCEPTION  4

extern TX_THREAD       *_tx_thread_current_ptr;

static ULONG  _nx_bsd_serv_list_len;
static struct NX_BSD_SERVICE_LIST  *_nx_bsd_serv_list_ptr;


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    bsd_initialize                                      PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets up all data structures and NetX, and ThreadX     */
/*    resources needed by the BSD compatibility layer. It is recommended  */
/*    to call this routine from tx_application_define.                    */
/*                                                                        */
/*  INPUTS                                                                */
/*                                                                        */
/*    *default_ip                           NX_IP created for BSD API     */
/*    *default_pool                         Packet Pool used by BSD API   */
/*    *bsd_thread_stack_area                Stack memory pointer for the  */
/*                                            BSD thread stack space      */
/*     bsd_thread_stack_size                Size of thread stack          */
/*     bsd_thread_priority                  BSD thread priority           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                            Successful completion         */
/*    NX_BSD_BLOCK_POOL_ERROR               Error creating socket block   */
/*                                            pool                        */
/*    NX_BSD_EVENT_ERROR                    Error creating the event flag */
/*                                            group                       */
/*    NX_BSD_MUTEX_ERROR                    Error creating mutex          */
/*    NX_BSD_ENVIRONMENT_ERROR              Error environment             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                                Set memory                    */
/*    tx_block_pool_create                  Create a block pool           */
/*    tx_block_pool_delete                  Delete a block pool           */
/*    tx_event_flags_create                 Create event flag group       */
/*    tx_mutex_create                       Create protection mutex       */
/*    tx_mutex_delete                       Delete protection mutex       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Start-up code                                                       */
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
INT  bsd_initialize(NX_IP *default_ip, NX_PACKET_POOL *default_pool, CHAR *bsd_thread_stack_area, 
                    ULONG bsd_thread_stack_size, UINT bsd_thread_priority)
{

INT         i;
UINT        status;
ULONG       info; 

#ifndef NX_ENABLE_EXTENDED_NOTIFY_SUPPORT

    /* Error, return the error message.  */
    /* BSD doesn't work with out NX_ENABLE_EXTENDED_NOTIFY_SUPPORT option. */
    NX_BSD_ERROR(NX_BSD_ENVIRONMENT_ERROR, __LINE__);
    return(NX_BSD_ENVIRONMENT_ERROR);
#endif /* NX_ENABLE_EXTENDED_NOTIFY_SUPPORT */

    /* Create a block pool for dynamically allocating sockets.  */
    status =  tx_block_pool_create(&nx_bsd_socket_block_pool, "NetX BSD Socket Block Pool", sizeof(NX_TCP_SOCKET), 
                                   nx_bsd_socket_pool_memory, sizeof(nx_bsd_socket_pool_memory));

    /* Determine if the pool was created.  */
    if (status)
    {
    
        /* Error, return the error message.  */
        NX_BSD_ERROR(NX_BSD_BLOCK_POOL_ERROR, __LINE__);
        return(NX_BSD_BLOCK_POOL_ERROR);
    }

    /* Create a block pool for dynamically allocating addrinfo. */
    status = tx_block_pool_create(&nx_bsd_addrinfo_block_pool, "NetX BSD Addrinfo Block Pool", sizeof(struct addrinfo),
                                  nx_bsd_addrinfo_pool_memory, sizeof(nx_bsd_addrinfo_pool_memory));

    /* Determine if the pool was created. */
    if(status)
    {

        /* Error, return the error messafe. */
        NX_BSD_ERROR(NX_BSD_BLOCK_POOL_ERROR, __LINE__);

        /* Delete the block pool.  */
        tx_block_pool_delete(&nx_bsd_socket_block_pool);
        return(NX_BSD_BLOCK_POOL_ERROR);
        
    }

#if defined(NX_BSD_ENABLE_DNS) && defined (NX_DNS_ENABLE_EXTENDED_RR_TYPES)
    /* Create a block pool for dynamically allocating canonical name buffer. */
    status = tx_block_pool_create(&nx_bsd_cname_block_pool, "NetX BSD CNAME Block Pool", (NX_DNS_NAME_MAX + 1),
                                  nx_bsd_cname_pool_memory, sizeof(nx_bsd_cname_pool_memory));

    /* Determine if the pool was created. */
    if(status)
    {

        /* Error, return the error messafe. */
        NX_BSD_ERROR(NX_BSD_BLOCK_POOL_ERROR, __LINE__);

        /* Delete the block pool.  */
        tx_block_pool_delete(&nx_bsd_socket_block_pool);
        tx_block_pool_delete(&nx_bsd_addrinfo_block_pool);
        return(NX_BSD_BLOCK_POOL_ERROR);
        
    }
#endif

    nx_bsd_protection_ptr = &default_ip -> nx_ip_protection;

    /* Create the BSD event flag group.   */
    status =  tx_event_flags_create(&nx_bsd_events, "NetX BSD Events");
    
    /* Check the return status.  */
    if (status)
    {
        /* Delete the block pool.  */
        tx_block_pool_delete(&nx_bsd_socket_block_pool);
        tx_block_pool_delete(&nx_bsd_addrinfo_block_pool);
#if defined(NX_BSD_ENABLE_DNS) && defined (NX_DNS_ENABLE_EXTENDED_RR_TYPES)
        tx_block_pool_delete(&nx_bsd_cname_block_pool);
#endif

        /* Error present, return error code.  */
        NX_BSD_ERROR(NX_BSD_EVENT_ERROR, __LINE__);
        return(NX_BSD_EVENT_ERROR);
    }

    /* Set the array index to 0.  */
    nx_bsd_socket_array_index =  0;
    
    /* Loop through the BSD socket array and clear it out!  */
    for (i = 0; i < NX_BSD_MAX_SOCKETS; i++)
    {
    
        /* Clear the BSD socket structure.  */
        memset((VOID*) &nx_bsd_socket_array[i], 0, sizeof(NX_BSD_SOCKET));
    }

    /* Save the IP instance and NX_PACKET_POOL for BSD Socket API.  */
    nx_bsd_default_ip =           default_ip;
    nx_bsd_default_packet_pool =  default_pool;


    if ((bsd_thread_stack_area == TX_NULL) || (bsd_thread_stack_size == 0))
    {
        /* Return error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

#ifndef NX_BSD_TIMEOUT_PROCESS_IN_TIMER
    /* Create a thread for BSD socket features requiring periodic tasks.  */
    info = 0 ; 
    status = tx_thread_create(&nx_bsd_task_thread, "BSD thread task", nx_bsd_thread_entry, info,
                              bsd_thread_stack_area, bsd_thread_stack_size, bsd_thread_priority, 
                              bsd_thread_priority, 1, TX_AUTO_START);
           
     if (status != TX_SUCCESS)
     {
         /* Delete the event flag group.  */
         tx_event_flags_delete(&nx_bsd_events);

         /* Delete the block pool.  */
         tx_block_pool_delete(&nx_bsd_socket_block_pool);
         tx_block_pool_delete(&nx_bsd_addrinfo_block_pool);
#if defined(NX_BSD_ENABLE_DNS) && defined (NX_DNS_ENABLE_EXTENDED_RR_TYPES)
        tx_block_pool_delete(&nx_bsd_cname_block_pool);
#endif

         /* Error, return the error message.  */
         NX_BSD_ERROR(NX_BSD_THREAD_ERROR, __LINE__);

         /* Return an error.  */
         return(NX_IP_INTERNAL_ERROR);
     }
#else

    info = 0 ; 

    /* Create a one shot timer. Do not activate it. We will use it if 
       a socket being disconnected is NOT enabled for REUSEADDR socket option. */
    status = tx_timer_create(&nx_bsd_timer, "BSD Timer", 
                             nx_bsd_timer_entry, info,   
                             NX_BSD_TIMER_RATE, NX_BSD_TIMER_RATE, TX_AUTO_START);

    if (status != TX_SUCCESS)
    {

        /* Delete the event flag group.  */
        tx_event_flags_delete(&nx_bsd_events);

        /* Delete the block pool.  */
        tx_block_pool_delete(&nx_bsd_socket_block_pool);
        tx_block_pool_delete(&nx_bsd_addrinfo_block_pool);
#if defined(NX_BSD_ENABLE_DNS) && defined (NX_DNS_ENABLE_EXTENDED_RR_TYPES)
        tx_block_pool_delete(&nx_bsd_cname_block_pool);
#endif

#ifndef NX_BSD_TIMEOUT_PROCESS_IN_TIMER
        /* Delete the thread. */
        tx_thread_delete(&nx_bsd_task_thread);
#endif
        /* Error, return the error message.  */
        NX_BSD_ERROR(NX_BSD_THREAD_ERROR, __LINE__);

        /* Return an error.  */
        return(NX_IP_INTERNAL_ERROR);
    }
#endif

#ifdef NX_BSD_RAW_SUPPORT
    _nx_driver_hardware_packet_received_callback = _nx_bsd_hardware_packet_received;
#endif /* NX_BSD_RAW_SUPPORT */

    /* Calculate BSD system timer rate. */
    nx_bsd_timer_rate = (NX_IP_PERIODIC_RATE + (NX_TCP_FAST_TIMER_RATE - 1)) / NX_TCP_FAST_TIMER_RATE;

    /* Return success!  */    
    return(NX_SOC_OK);   
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_bsd_timeout_process                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for sockets waiting to make a TCP connection.  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                         Obtain exclusive access to     */
/*    tx_mutex_put                         Release exclusive access       */
/*    nx_tcp_server_socket_unaccept        Remove socket from listen list */
/*    nx_tcp_server_socket_relisten        Restore socket to listening    */
/*    nx_tcp_server_socket_accept          Accept to connection request   */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    ThreadX                                                             */
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
static VOID nx_bsd_timeout_process()
{

INT             i;
ULONG           status;
INT             master_socket_index;
NX_BSD_SOCKET  *bsd_socket_ptr;


   /* Obtain the BSD lock. */
   status = tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);
   
   if(status)
   {
       /* Mutex operation failed.  This should be fatal. */
       return;
   }

   for( i = 0; i < NX_BSD_MAX_SOCKETS; i++)
   {

       /* Skip the unused sockets. */
       if(!(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
       {

           continue;
       }

       /* Skip if it is not TCP server socket. */
       if((nx_bsd_socket_array[i].nx_bsd_socket_tcp_socket == NX_NULL) ||
          ((nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_CLIENT)))
       {
           continue;
       }

       /* Check for sockets trying to make a TCP connection.  
          Detect that the socket state is CLOSED, which is an indication
          that the attempted connection failed, and we shall signal any pending
          select on the socket. */
       if(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTION_INPROGRESS)
       {

           /* Is the NetX socket closed? */
           if(nx_bsd_socket_array[i].nx_bsd_socket_tcp_socket -> nx_tcp_socket_state == NX_TCP_CLOSED)
           {

               /* Yes. Set up a local pointer to the BSD socket. */
               bsd_socket_ptr = &nx_bsd_socket_array[i];
               
               /* Is this a secondary socket (passive open)? */
               if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_SECONDARY_SOCKET)
               {

                   /* Yes; Is the socket is connected yet? */
                   if(!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED))
                   {

                       /* No; Turn off the disconnection_request flag. */
                       bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_DISCONNECTION_REQUEST);

                       /* Remove the underlying NetX socket from the listen state. */
                       nx_tcp_server_socket_unaccept(bsd_socket_ptr -> nx_bsd_socket_tcp_socket);

                       /* Check if a listen request is queued up for this socket. */
                       nx_bsd_tcp_pending_connection(bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_port,
                                                     bsd_socket_ptr -> nx_bsd_socket_tcp_socket);

                       /* Relisten on this socket. */
                       status = nx_tcp_server_socket_relisten(nx_bsd_default_ip, 
                                                              bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_port,
                                                              bsd_socket_ptr -> nx_bsd_socket_tcp_socket);
                       /* Set the socket to accept the connection. */                       
                       nx_tcp_server_socket_accept(bsd_socket_ptr -> nx_bsd_socket_tcp_socket, NX_NO_WAIT);

                       /* Check the result of the relisten call. */
                       if(status == NX_CONNECTION_PENDING)
                       {

                           bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTION_INPROGRESS;
                       }
                       else if(status != NX_SUCCESS)
                       {

                                
                           /* Failed the relisten on the secondary socket.  Set the error code on the 
                              master socket, and wake it up. */
                           
                           master_socket_index = (bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_master_socket_id;
                           
                           nx_bsd_socket_array[master_socket_index].nx_bsd_socket_status_flags |= NX_BSD_SOCKET_ERROR;
                           nx_bsd_set_error_code(&nx_bsd_socket_array[master_socket_index], status);
                           
                           nx_bsd_select_wakeup((UINT)master_socket_index, (FDSET_READ | FDSET_WRITE | FDSET_EXCEPTION));
                       }
                   }                       
               }
               else
               {
                   /* The underlying socket is closed.  This indicates an error, and since is a non-blocking
                      socket, we need to wake up the corresponding thread. */
               
                   /* Mark this socket as error, and remove the CONNECT and INPROGRESS flags */
                   nx_bsd_socket_array[i].nx_bsd_socket_status_flags |= NX_BSD_SOCKET_ERROR;
                   nx_bsd_socket_array[i].nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTION_INPROGRESS);
                   nx_bsd_socket_array[i].nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTED);
                   nx_bsd_socket_array[i].nx_bsd_socket_error_code = ECONNREFUSED;

                   /* Wake up the socket that could be listening on it. */
                   /* Notice that on error the both read and write are selectable. */
                   nx_bsd_select_wakeup((UINT)i, FDSET_READ | FDSET_WRITE | FDSET_EXCEPTION);
               }
           }
       }
   }

   /* Release the mutex. */
   tx_mutex_put(nx_bsd_protection_ptr);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_bsd_thread_entry                                 PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for events indicating BSD TCP socket tasks are */
/*    waiting to  be performed.                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_get                   Check for registered events    */
/*    nx_bsd_timeout_process               Process BSD tasks              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    ThreadX                                                             */
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

#ifndef NX_BSD_TIMEOUT_PROCESS_IN_TIMER
VOID nx_bsd_thread_entry(ULONG info)
{
    NX_PARAMETER_NOT_USED(info);

    while(1)
    {

        /* Wait for timeout. */
        tx_thread_sleep(NX_BSD_TIMER_RATE);

        /* Timeout process. */
        nx_bsd_timeout_process();
    }
}
#endif                      

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    socket                                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Creates a TCP or UDP socket, which may then be used as an end point */
/*    of communication for sending and receiving data using the specified */
/*    protocol.                                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    protocolFamily                        Protocol family e.g AF_INET   */
/*    type                                  Type of the socket TCP or UDP */
/*    protocol                              Socket protocol               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    socket descriptor                     On success                    */
/*    NX_SOC_ERROR (-1)                     On failure                    */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                                Clears memory                 */
/*    nx_tcp_socket_create                  Create TCP BSD Socket         */
/*    nx_udp_socket_create                  Create UDP BSD Socket         */
/*    nx_tcp_socket_receive_notify          TCP receive notify function   */
/*    nx_udp_socket_receive_notify          UDP receive notify function   */
/*    tx_block_allocate                     Allocate socket memory        */
/*    tx_block_release                      Release socket memory         */
/*    tx_mutex_get                          Get protection                */
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
INT  socket(INT protocolFamily, INT type, INT protocol)
{

INT             i;
UINT            status;
NX_TCP_SOCKET   *tcp_socket_ptr;
NX_UDP_SOCKET   *udp_socket_ptr;
VOID            *socket_memory = NX_NULL;
NX_BSD_SOCKET   *bsd_socket_ptr;


    NX_PARAMETER_NOT_USED(protocol);

    /* Check for a supported protocol family.  */
    if (protocolFamily == AF_INET)
    {
    }
    else
#if defined(NX_BSD_RAW_SUPPORT) || defined(NX_BSD_RAW_PPPOE_SUPPORT)
    if (protocolFamily == AF_PACKET)
    {
    }
    else
#endif /* defined(NX_BSD_RAW_SUPPORT) || defined(NX_BSD_RAW_PPPOE_SUPPORT) */
    {

        /* Set the socket error. */
        set_errno(EAFNOSUPPORT);

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Check for a supported socket type.   */
#if defined(NX_ENABLE_IP_RAW_PACKET_FILTER) || defined(NX_BSD_RAW_PPPOE_SUPPORT) || defined(NX_BSD_RAW_SUPPORT)
    if ((type != SOCK_STREAM) && (type != SOCK_DGRAM) && (type != SOCK_RAW))
#else
    if ((type != SOCK_STREAM) && (type != SOCK_DGRAM))
#endif
    {

        /* Set the socket error. */
        set_errno(EPROTOTYPE);

        /* Invalid type.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }    

#if defined(NX_BSD_RAW_SUPPORT) || defined(NX_BSD_RAW_PPPOE_SUPPORT)
    /* An extra check when BSD RAW Packet type is enabled:
       Only RAW_SOCKET type is supported in AF_PACKET family. */
    if((protocolFamily == AF_PACKET) && (type != SOCK_RAW))
    {
        /* Set the socket error. */
        set_errno(EPROTOTYPE);

        /* Invalid type.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }    
#endif /* defined(NX_BSD_RAW_SUPPORT) || defined(NX_BSD_RAW_PPPOE_SUPPORT) */


    /* Obtain the BSD protection socket.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status)
    {

        /* Set the socket error. */
        set_errno(EACCES);

        /* Error getting the protection mutex.  */
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Check whether IP fast timer is created or not. */
    if ((nx_bsd_ip_fast_periodic_timer_entry == NX_NULL) ||
        (nx_bsd_default_ip -> nx_ip_tcp_fast_periodic_timer.tx_timer_internal.tx_timer_internal_timeout_function != _nx_bsd_fast_periodic_timer_entry))
    {

        /* BSD socket requires a fast periodic timer to calculate wait option in recv() function. */
        /* Create IP fast periodic timer. */
        if (nx_bsd_default_ip -> nx_ip_tcp_fast_periodic_timer.tx_timer_id != TX_TIMER_ID)
        {
            _nx_tcp_enable(nx_bsd_default_ip);
        }

        /* Replace timer expiration function entry. */
        nx_bsd_ip_fast_periodic_timer_entry = nx_bsd_default_ip -> nx_ip_tcp_fast_periodic_timer.tx_timer_internal.tx_timer_internal_timeout_function;
        nx_bsd_default_ip -> nx_ip_tcp_fast_periodic_timer.tx_timer_internal.tx_timer_internal_timeout_function = _nx_bsd_fast_periodic_timer_entry;
    }

    /* Now find a free slot in the BSD socket array.  */
    for (i = 0; i < NX_BSD_MAX_SOCKETS; i++)  
    {

        /* See if this entry is available.  Check the in use flag. */
        if (!(nx_bsd_socket_array[nx_bsd_socket_array_index].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
        {

            /* Yes, Ok to use this socket. */

            /* Clear the entire structure.  */
            memset((VOID*) &nx_bsd_socket_array[nx_bsd_socket_array_index], 0, sizeof(NX_BSD_SOCKET));
            nx_bsd_socket_array[nx_bsd_socket_array_index].nx_bsd_socket_id = (INT)nx_bsd_socket_array_index;

            /* Mark this socket as in-use.  */
            nx_bsd_socket_array[nx_bsd_socket_array_index].nx_bsd_socket_status_flags |=  NX_BSD_SOCKET_IN_USE;
            
            /* Get out of the loop.  */
            break;
        }
        else
        {

            /* Try the next socket.  */
            nx_bsd_socket_array_index++;

            /* Check if we need to wrap around to the start of the socket table.  */
            if (nx_bsd_socket_array_index >= NX_BSD_MAX_SOCKETS)
            {
            
                /* Reset the index to 0.  */
                nx_bsd_socket_array_index =  0;
            }
        }
    }
    
    /* Check if a free socket was found.  */
    if (i >= NX_BSD_MAX_SOCKETS)
    {

        /* No, set the error status and return. */

        /* Set the socket error. */
        set_errno(ENFILE);

        /* Release the mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
            
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Mark the location of the free socket. */
    i = (INT)nx_bsd_socket_array_index;

    /* Update the socket index to the next entry.  */
    nx_bsd_socket_array_index++;

    /* Check if we need to wrap around to the start of the table.  */
    if (nx_bsd_socket_array_index >= NX_BSD_MAX_SOCKETS)
    {
            
        /* Reset the index to 0.  */
        nx_bsd_socket_array_index =  0;
    }

    /* Set up a pointer to the BSD socket to use. */
    bsd_socket_ptr =  &nx_bsd_socket_array[i];

    /* For TCP or UDP sockets we need to allocate memory to create the NetX socket */

    if ((type == SOCK_STREAM) || (type == SOCK_DGRAM))
    {
    
        /* Allocate a socket from the block pool.  */
        status =  tx_block_allocate(&nx_bsd_socket_block_pool, &socket_memory, NX_BSD_TIMEOUT);
        
        /* Check for error status.  */
        if (status != TX_SUCCESS)
        {
    
            /* Set the socket error. */
            set_errno(ENOMEM); 
    
            /* Clear the allocated internal BSD socket.  */
            bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_IN_USE);
     
            /* Release the mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);
                
            /* Error getting NetX socket memory.  */
            NX_BSD_ERROR(NX_BSD_BLOCK_POOL_ERROR, __LINE__);
            return(NX_SOC_ERROR); 
        }

        /* Clear the socket memory.  */
        memset((VOID*) socket_memory, 0, sizeof(NX_TCP_SOCKET));

    }

    /* Is this a stream socket e.g. TCP?  */
    if (type == SOCK_STREAM)
    {
        bsd_socket_ptr -> nx_bsd_socket_protocol = NX_PROTOCOL_TCP;    
    
        /* Mark the master/secondary socket id as invalid. */
        (bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_master_socket_id = NX_BSD_MAX_SOCKETS;
        (bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id = NX_BSD_MAX_SOCKETS;

        /* Yes, allocate memory for a TCP socket.  */
        tcp_socket_ptr =  (NX_TCP_SOCKET *) socket_memory;
    
        /* Create a NetX TCP socket. */
        /* Note that the nx_bsd_tcp_socket_disconnect_notify is invoked when an 
           established connection is disconnected.  
           The disconnect_complete_notify is called for all types of disconnect,
           including the ones covered by tcp_socket_disconnect_notify. */
           
        status =  nx_tcp_socket_create(nx_bsd_default_ip, tcp_socket_ptr, "NetX BSD TCP Socket", 
                                       NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, NX_BSD_TCP_WINDOW, NX_NULL,
                                       nx_bsd_tcp_socket_disconnect_notify);

        /* Check for a successful status.  */
        if (status == NX_SUCCESS)
        {
            
            /* Register a receive notify callback.  */
            status =  nx_tcp_socket_receive_notify(tcp_socket_ptr, nx_bsd_tcp_receive_notify);

            /* Check for invalid input. */
            if (status != NX_SUCCESS)
            {

                /* Set the socket error if extended socket options enabled. */
                set_errno(EINVAL);  

                /* Release the allocated socket memory block.  */
                tx_block_release(socket_memory);

                /* Release the mutex.  */
                tx_mutex_put(nx_bsd_protection_ptr);

                /* Error getting NetX socket memory.  */
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return(NX_SOC_ERROR); 
            }

#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT

            /* Set the SYN received notify function */
            tcp_socket_ptr -> nx_tcp_socket_syn_received_notify = nx_bsd_tcp_syn_received_notify;
#endif /* NX_DISABLE_EXTENDED_NOTIFY_SUPPORT */

#ifdef NX_ENABLE_TCP_KEEPALIVE
            /* Set the keep alive feature to disabled. */
            tcp_socket_ptr -> nx_tcp_socket_keepalive_enabled = NX_FALSE;
#endif /* NX_ENABLE_TCP_KEEPALIVE */

            /* Set the socket reuse feature to enabled. This is the default NetX socket behavior. */ 
            bsd_socket_ptr -> nx_bsd_socket_option_flags |= NX_BSD_SOCKET_ENABLE_OPTION_REUSEADDR; 

#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
            /* Register an establish notify callback for the specified server socket with NetX.  */
            nx_tcp_socket_establish_notify(tcp_socket_ptr, nx_bsd_tcp_establish_notify);

            /* Register a disconnect complete notify callback for the specified server socket with NetX.  */
            /* The callback function is the same as the one used for TCP disconnect callback. */
            status += nx_tcp_socket_disconnect_complete_notify(tcp_socket_ptr, nx_bsd_tcp_socket_disconnect_notify);
#endif /* NX_DISABLE_EXTENDED_NOTIFY_SUPPORT */

            /* Return successful completion.  */

            /* Save the TCP pointer in the appropriate place.  */
            bsd_socket_ptr -> nx_bsd_socket_tcp_socket =  tcp_socket_ptr;

            /* Set up pointer in the NetX socket back to the BSD socket.   */
            tcp_socket_ptr -> nx_tcp_socket_reserved_ptr =  (VOID *) i;


        }
    }
    else if (type == SOCK_DGRAM)
    {

        bsd_socket_ptr -> nx_bsd_socket_protocol = NX_PROTOCOL_UDP;

        /* Make a double circular list. */
        bsd_socket_ptr -> nx_bsd_socket_next = bsd_socket_ptr;
        bsd_socket_ptr -> nx_bsd_socket_previous = bsd_socket_ptr;
    
        /* Allocate memory for a UDP socket.  */
        udp_socket_ptr =  (NX_UDP_SOCKET *) socket_memory;

        /* Create a NetX UDP socket */
        status =  nx_udp_socket_create(nx_bsd_default_ip, udp_socket_ptr, "NetX BSD UDP Socket", 
                                       NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 
                                       (nx_bsd_default_packet_pool -> nx_packet_pool_total)/8+1);

        /* Check for successful result. */
        if (status == NX_SUCCESS)
        {

            /* Register a receive notify callback.  */
            status = nx_udp_socket_receive_notify(udp_socket_ptr, nx_bsd_udp_receive_notify);
            
            /* Check for errors.  */
            if (status != NX_SUCCESS)
            {
    
                /* Release the allocated socket memory block.  */
                tx_block_release(socket_memory);

                /* Release the mutex.  */
                tx_mutex_put(nx_bsd_protection_ptr);

                /* Set the socket error if extended socket options enabled. */
                set_errno(EINVAL);  
    
                /* Error getting NetX socket memory.  */
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return(NX_SOC_ERROR); 
            }
    
            /* Save the UDP pointer in the BSD socket.  */
            bsd_socket_ptr -> nx_bsd_socket_udp_socket =  udp_socket_ptr;
    
            /* Set the reserved UDP socket pointer back to the BSD socket.  */
            udp_socket_ptr -> nx_udp_socket_reserved_ptr =  (VOID *) (i + 0x00010000);
        }
    }
#if defined(NX_ENABLE_IP_RAW_PACKET_FILTER) || defined(NX_BSD_RAW_PPPOE_SUPPORT) || defined(NX_BSD_RAW_SUPPORT)
    else if (type == SOCK_RAW)
    {


        if(protocolFamily == AF_PACKET)
        {
#if   defined(NX_BSD_RAW_SUPPORT)
            bsd_socket_ptr -> nx_bsd_socket_local_bind_interface = NX_BSD_LOCAL_IF_INADDR_ANY;
            bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index = NX_BSD_LOCAL_IF_INADDR_ANY;
#endif /* NX_BSD_RAW_PPPOE_SUPPORT */
        }

    }
#endif  /* NX_ENABLE_IP_RAW_PACKET_FILTER || NX_BSD_RAW_PPPOE_SUPPORT || NX_BSD_RAW_SUPPORT */

    else  
    {
        /* Not a supported socket type.   */
       set_errno(EOPNOTSUPP);

        /* Invalid type.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Set the protocol family: AF_INET or AF_INET6.   */
    bsd_socket_ptr -> nx_bsd_socket_family = (ULONG)protocolFamily;

    /* Set the maximum receive queue depth. */
    if(bsd_socket_ptr -> nx_bsd_socket_protocol != NX_PROTOCOL_TCP)
    {
    
        bsd_socket_ptr -> nx_bsd_socket_received_packet_count_max = NX_BSD_SOCKET_QUEUE_MAX;
    }

    /* Check for error creating the NetX socket.  */
    if (status != NX_SUCCESS)
    {
    
        /* Release the BSD protection.  */

        /* Clear the BSD socket in use flag.  */
        bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_IN_USE);

        if ((type == SOCK_DGRAM) || (type == SOCK_STREAM))
        {
            /* Release the socket memory block allocated for TCP or UDP socket.  */
            tx_block_release(socket_memory);
        }

        /* Release the mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        /* Error present, return error code.  */
        NX_BSD_ERROR(status, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Release the mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);

    /* Return success!  */
    return(i + NX_BSD_SOCKFD_START);
}      


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    connect                                             PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Establishes a connection between a client socket and a remote server*/
/*    socket associated with the remote address, if any. Upon returning   */
/*    successfully, the given socket's local and remote IP address and    */    
/*    port information are filled in. If the socket was not previously    */
/*    bound to a local port, one is assigned randomly.                    */
/*                                                                        */
/*    For TCP sockets, connect() completes with a connection handshake is */
/*    complete, or if an error occurs.   A TCP negotiation is performed   */
/*    to open a connection and success implies the existence of a reliable*/
/*    channel to that socket.                                             */
/*                                                                        */
/*    For UDP sockets, the connection is established simply by setting the*/
/*    supplied destination (remote) IP address and port for the remote    */
/*    host.                                                               */
/*                                                                        */
/*    For non blocking sockets, the function returns immediately if a     */
/*    connection is not possible.  The socket thread error is set to      */
/*    EINPROGRESS to distinguish from blocking sockets.                   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*     sockID                               Socket descriptor             */
/*    *remoteAddress                        Remote address structure      */
/*     addressLength                        Address structure length      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SOC_OK (0)                         If success                    */
/*    NX_SOC_ERROR (-1)                     If failure or if called with  */
/*                                            an UDP socket               */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_ip_status_check                    Check to make sure link is up */
/*    nx_tcp_client_socket_bind             Bind a TCP socket to a port   */
/*    tx_mutex_get                          Get protection                */
/*    tx_mutex_put                          Release protection            */
/*    tx_thread_identify                    Get current thread pointer    */
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
INT  connect(INT sockID, struct sockaddr *remoteAddress, INT addressLength)
{
UINT                status;
NX_TCP_SOCKET       *tcp_socket_ptr;
NX_UDP_SOCKET       *udp_socket_ptr;
NX_BSD_SOCKET       *bsd_socket_ptr;
ULONG               timeout;
ULONG               actual_status;

    /* Check for a valid socket ID.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error. */
        set_errno(EBADF);

        /* Return an error. */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Adjust the sockID to index into the BSD socket table.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(nx_bsd_default_ip, NX_IP_INITIALIZE_DONE, &actual_status, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {
    
        /* Set the socket error. */
        set_errno(EFAULT);

        /* Return an error. */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Set a pointer to the BSD socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    /* Make sure the socket is valid. */
    if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
    {
        
        /* Socket is no longer in use.   */

        /* Set the socket error if extended socket options enabled. */
        set_errno(EBADF);

        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }    

    /* Obtain the BSD protection.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {
        
        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);  

        /* Return an error. */
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Check whether supplied address structure and length is valid */
    if (remoteAddress == NX_NULL ) 
    {

        /* For UDP socket , a NULL remoteAddress dis-associate
           a remote address bound to the socket. */
        if (bsd_socket_ptr -> nx_bsd_socket_protocol != NX_PROTOCOL_TCP)
        {
            bsd_socket_ptr -> nx_bsd_socket_peer_ip = 0;
            bsd_socket_ptr -> nx_bsd_socket_peer_port = 0;
            
            /* Clear the connect flag. */
            bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTED);

            /* All done.  Return. */

            /* Release the mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            return(NX_SOC_OK);

        }
        else
        {
            /* For TCP socket, each socket can only be connected once, and
               the remote address must be set correctly. */

            /* Release the mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);
            /* Set the socket error if extended socket options enabled. */
            set_errno(EAFNOSUPPORT);

            /* Return an error. */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR);
        }
    }


    /* Check if the remote address family matches the local BSD socket address family. */
    if((remoteAddress -> sa_family != bsd_socket_ptr -> nx_bsd_socket_family) ||
       ((remoteAddress -> sa_family == AF_INET) && (addressLength != sizeof(struct sockaddr_in))))
    {
        
        /* Mismatch! */

        /* Release the mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EAFNOSUPPORT);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(ERROR);
    }

    /* Check the socket family type.  */
    if(remoteAddress -> sa_family == AF_INET)
    {

        /* This is an IPv4 socket type. */

        /* Set the UDP remote host IP address and port for the UDP 'connection'; for NetX 
           set the IP version. */ 
        /* NetX API expects multi byte values to be in host byte order. 
           Therefore ntohl/s are used to make the conversion. */
        bsd_socket_ptr -> nx_bsd_socket_peer_ip = htonl(((struct sockaddr_in *) remoteAddress ) -> sin_addr.s_addr);  
        bsd_socket_ptr -> nx_bsd_socket_peer_port =  htons(((struct sockaddr_in *) remoteAddress ) -> sin_port);
    }
    else

    {
        
        /* Address family not supported. */

        /* Release the mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EAFNOSUPPORT);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(ERROR);
    }


    /* Handle the UDP 'connection' request.  */
    if (bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_UDP)
    {

        udp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_udp_socket;

        /* Check to see if the UDP socket is already bound.  */
        if(!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_BOUND))
        {

            /* Not yet, bind to a randomly selected available free port.  */
            status =  nx_udp_socket_bind(udp_socket_ptr, NX_ANY_PORT, NX_BSD_TIMEOUT);

            /* Check for error.  */
            if (status != NX_SUCCESS)
            {

                /* Release the mutex.  */
                tx_mutex_put(nx_bsd_protection_ptr);
                
                /* Set the socket error based on NetX error status return. */
                nx_bsd_set_error_code(bsd_socket_ptr, status);
                
                /* Return an error.  */
                NX_BSD_ERROR(ERROR, __LINE__);
                return(ERROR);
            }

            /* Bind is successful. Obtain the port number. */
            bsd_socket_ptr -> nx_bsd_socket_local_port = (USHORT)udp_socket_ptr -> nx_udp_socket_port;
            bsd_socket_ptr -> nx_bsd_socket_local_bind_interface = NX_BSD_LOCAL_IF_INADDR_ANY;
            bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index = NX_BSD_LOCAL_IF_INADDR_ANY;
            bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_BOUND;
       }

       /* Mark the socket as connected. */
       bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTED;
       
       /* Release the mutex.  */
       tx_mutex_put(nx_bsd_protection_ptr);

       /* Return successful status.  */
       return(NX_SOC_OK);
    }
    else if (bsd_socket_ptr -> nx_bsd_socket_protocol != NX_PROTOCOL_TCP)
    {

        /* This is not UDP or TCP socket. */

        /* Release the mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
        
        /* Return successful status.  */
        return(NX_SOC_OK);
    }

    /* This is a TCP BSD socket. */

    /* If the socket is already connected. */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED)
    {

        /* If INPROGRESS is set, clear the INPROGRESS flag and return OK. 
           The INPROGRESS flag needs to be cleared so the next connect call would return EISCONN */
        if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTION_INPROGRESS)
        {

            bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTION_INPROGRESS);
        
            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            return(NX_SOC_OK); 
        }

        /* Already connected. */
        set_errno(EISCONN);
        
        tx_mutex_put(nx_bsd_protection_ptr);
                
        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR); 

    }

    /* If the socket is marked as EINPROGRESS, return EALREADY. */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTION_INPROGRESS)
    {
        

        set_errno(EALREADY);
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);            

        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
            
    }
    /* If the socket has an error */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR) 
    {                                                                        
        INT errcode = bsd_socket_ptr -> nx_bsd_socket_error_code;    

        /* Now clear the error code. */
        bsd_socket_ptr -> nx_bsd_socket_error_code = 0;
        
        /* Clear the error flag.  The application is expected to close the socket at this point.*/  
        bsd_socket_ptr -> nx_bsd_socket_status_flags = 
            bsd_socket_ptr -> nx_bsd_socket_status_flags & ((ULONG)(~NX_BSD_SOCKET_ERROR)); 
                                                                             
        set_errno(errcode);                                                  
                                                                             
        /* Release the protection mutex.  */                                  
        tx_mutex_put(nx_bsd_protection_ptr);                                     
                                                                              
        /* Return an error.  */                                               
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);                                 
                                                                              
        /* At this point the error flag is cleared.  Application should       
           detect and handle the error codition. This socket is still bound   
           to the port (either the application called bind(), or a bind       
           operation was executed as part of the connect call) is able to     
           handle another "connect" call, or be closed. */                    
        return(NX_SOC_ERROR);                                                 
    }                                                                        

    /* Set a NetX tcp pointer.  */
    tcp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_tcp_socket;

    /* Mark this as a client TCP socket. */
    bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CLIENT;

    /* Is the TCP socket already bound?  */
    if (tcp_socket_ptr -> nx_tcp_socket_port == 0)
    {

        /* Not yet; bind to a randomly selected available free port. */

        /* Call NetX TCP bind service with NX_NO_WAIT.  */
        status =  nx_tcp_client_socket_bind(tcp_socket_ptr, NX_ANY_PORT, NX_NO_WAIT);

        /* Check for error.  */
        if (status != NX_SUCCESS)
        {

            /* Clear the client socket flag.  */
            bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CLIENT);

            /* Set the socket error depending on NetX error status return. */
            nx_bsd_set_error_code(bsd_socket_ptr, status);

            /* Return an error.  */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);

            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);            

            return(NX_SOC_ERROR);
        }

        /* Mark the socket as bound. */
        bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_BOUND;
        bsd_socket_ptr -> nx_bsd_socket_local_port = (USHORT)tcp_socket_ptr -> nx_tcp_socket_port;
        bsd_socket_ptr -> nx_bsd_socket_local_bind_interface = NX_BSD_LOCAL_IF_INADDR_ANY;
        bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index = NX_BSD_LOCAL_IF_INADDR_ANY;
        
    }

    /* Mark this BSD socket as busy.  */
    bsd_socket_ptr -> nx_bsd_socket_busy = tx_thread_identify();

    /* Attempt to make the connection.  If the socket is non-blocking,
       set the timeout to 0.  Otherwise, use wait-forever */
    if (bsd_socket_ptr -> nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING)
    {

        /* Yes, the socket is enabled for non blocking. Do not wait.  */
        timeout = 0;
    }
    else
    {
        /* This call may be blocked internally. Release the mutex
           so the nx_tcp_client_socket_connect can suspend waiting
           for a connection. */
        timeout = NX_WAIT_FOREVER;
        tx_mutex_put(nx_bsd_protection_ptr);            
    }        
    
    /* Make the connection. */
    status =  nx_tcp_client_socket_connect(tcp_socket_ptr, (bsd_socket_ptr -> nx_bsd_socket_peer_ip), bsd_socket_ptr -> nx_bsd_socket_peer_port, timeout);
    if(timeout != 0)
    {
        /* The mutex was released prior to the call.  Accquire the mutex
           again. */
        tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);
        
        /* Verify that the socket is still valid. */
        if(!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
        {
            /* The socket is no longer in use. */

            /* Set the socket error code. */
            set_errno(EBADF);

            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            /* Return error code.  */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR);
        }

        if (status == NX_NOT_CONNECTED)
        {

            if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR) || 
                (tcp_socket_ptr -> nx_tcp_socket_timeout_retries >= tcp_socket_ptr -> nx_tcp_socket_timeout_max_retries))
            {

                /* Connect timeouts since NX_BSD_SOCKET_ERROR is not set or 
                 * number of timeout retry has been exceeded. */
                status = NX_WAIT_ABORTED;
            }

            bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_ERROR;
            bsd_socket_ptr -> nx_bsd_socket_error_code = ENOTCONN;
        }
    }

    /* Check for an error.  */
    if (status != NX_SUCCESS)
    {

        /* Set the socket error depending on NetX error status return. */
        nx_bsd_set_error_code(bsd_socket_ptr, status);


        /* Make sure this thread is still the owner.  */
        if (bsd_socket_ptr -> nx_bsd_socket_busy == tx_thread_identify())
        {

            /* Clear the busy flag.  */
            bsd_socket_ptr -> nx_bsd_socket_busy =  TX_NULL;
        }
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Return error code.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* At this point NX TCP connect service returns success, so the connection is established. */

    /* Mark the socket as connected. */
    bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTED;

    /* Clear the CONNECTION_INPROGRESS flag. */
    bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTION_INPROGRESS);

    /* Mark the connection_request flag */
    bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTION_REQUEST;

    /* Make sure thread making the bind call is the current thread.  */
    if (bsd_socket_ptr -> nx_bsd_socket_busy == tx_thread_identify())
    {
    
        /* OK to clear the busy flag.  */
        bsd_socket_ptr -> nx_bsd_socket_busy =  TX_NULL;

        /* Check if the connect call was successful.  */
        if (status == NX_SUCCESS)
        {    

            /* It was. Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            /* Successful connection. Return the success status.  */
            return(NX_SOC_OK);
        }
    }    
    
    /* Error condition: the thread that was executing connect is not the current thread. */
    
    /* Clear the connected flags and peer infomration .*/
    bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTED);
    bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTION_REQUEST);
    bsd_socket_ptr -> nx_bsd_socket_source_ip_address = 0;
    bsd_socket_ptr -> nx_bsd_socket_source_port = 0;

    /* Release the protection mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);

    /* Set the socket error. */
    set_errno(EINTR); 

    /* Return an error.  */        
    NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
    return(NX_SOC_ERROR);
} 

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    bind                                                PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function binds a socket to a local port. The port in the struct*/
/*    in the struct sockaddr structure may be wildcarded, in which case   */
/*    NetX will select a port number.                                     */
/*                                                                        */
/*    To wildcard the port, set the sin_port field of the address to 0.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    sockID                                Socket descriptor             */
/*    *localAddress                         Populated socket address      */
/*    addressLength                         Socket address length         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SOC_OK (0)                         If success                    */
/*    NX_SOC_ERROR (-1)                     If failure                    */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_ip_status_check                    Check for link up             */
/*    nx_tcp_client_socket_bind             Binds a TCP socket to a port  */
/*    nx_udp_client_socket_bind             Binds a UDP socket to a port  */
/*    tx_mutex_get                          Get protection                */
/*    tx_mutex_put                          Release protection            */
/*    tx_thread_identify                    Gets the current thread       */
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
INT  bind(INT sockID, struct sockaddr *localAddress, INT addressLength)     
{

INT                 local_port = 0;
UINT                status;
NX_TCP_SOCKET       *tcp_socket_ptr;
NX_UDP_SOCKET       *udp_socket_ptr;
NX_BSD_SOCKET       *bsd_socket_ptr;
INT                 i;
INT                 address_conflict;


    /* Check for invalid socket ID.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error. */
        set_errno(EBADF);

        /* Error, invalid socket ID.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Check for a valid input local address and address length input buffer.  */
    if ((localAddress == NX_NULL ) || (addressLength == 0))
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EFAULT);

        /* Error, invalid local address. */ 
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);        
    }

    if (((localAddress -> sa_family == AF_INET) && (addressLength != sizeof(struct sockaddr_in))))
    {
        set_errno(EAFNOSUPPORT);
            
        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;
    
    /* Get the protection mutex.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);

        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Set up a pointer to the BSD socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    /* See if the socket is still in use.  */
    if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
    {
        
        /* Socket is no longer in use.   */

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EBADF);

        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* If the socket has an error */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR) 
    {     

        /* Clear the error flag.  The application is expected to close the socket at this point.*/  
        bsd_socket_ptr -> nx_bsd_socket_status_flags = 
            bsd_socket_ptr -> nx_bsd_socket_status_flags & (ULONG)(~NX_BSD_SOCKET_ERROR); 
                                                                             
        set_errno(bsd_socket_ptr -> nx_bsd_socket_error_code);

        /* Clear the error code. */
        bsd_socket_ptr -> nx_bsd_socket_error_code = 0;

        /* Release the protection mutex.  */                                  
        tx_mutex_put(nx_bsd_protection_ptr);                                     
                                                                              
        /* Return an error.  */                                               
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);                                 
                                                                              
        /* At this point the error flag is cleared.  Application should       
           detect and handle the error codition. This socket is still bound   
           to the port (either the application called bind(), or a bind       
           operation was executed as part of the connect call) is able to     
           handle another "connect" call, or be closed. */                    
        return(NX_SOC_ERROR);                                                 
    }                                                                        

    /* Check the address family. */
    if (bsd_socket_ptr -> nx_bsd_socket_family != localAddress -> sa_family)
    {
        set_errno(EAFNOSUPPORT);
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
            
        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Check to see if the socket is already bound.  */
    if (bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_BOUND)
    {

        /* It is. */

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
            
        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Zero out the local bind info */
    bsd_socket_ptr -> nx_bsd_socket_local_bind_interface = 0;

    if(localAddress -> sa_family == AF_INET)
    {

    ULONG local_addr;
    INT if_index;

        /* Pickup the local port.  */
        local_port = ntohs(((struct sockaddr_in *) localAddress) -> sin_port);
    
        /* Pick up the local IP address */
        local_addr = ntohl(((struct sockaddr_in*)localAddress) -> sin_addr.s_addr);
        
        if(local_addr == INADDR_ANY)
        {

            bsd_socket_ptr -> nx_bsd_socket_local_bind_interface = NX_BSD_LOCAL_IF_INADDR_ANY;
            bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index = NX_BSD_LOCAL_IF_INADDR_ANY;
        }
        else
        {

            for(if_index = 0; if_index < NX_MAX_IP_INTERFACES; if_index++)
            {

                if((nx_bsd_default_ip -> nx_ip_interface[if_index].nx_interface_valid) &&
                   (nx_bsd_default_ip -> nx_ip_interface[if_index].nx_interface_ip_address == local_addr))
                {

                    bsd_socket_ptr -> nx_bsd_socket_local_bind_interface = (ULONG)(&nx_bsd_default_ip -> nx_ip_interface[if_index]);
                    bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index = (UINT)if_index;
                    break;
                }
            }
        }
    }
#ifdef NX_BSD_RAW_SUPPORT
    if ((localAddress -> sa_family == AF_PACKET) && (addressLength == sizeof(struct sockaddr_ll)))
    {
    UINT if_index;

        if_index = (UINT)(((struct sockaddr_ll *)localAddress) -> sll_ifindex);
        bsd_socket_ptr -> nx_bsd_socket_local_bind_interface = (ULONG)(&nx_bsd_default_ip -> nx_ip_interface[if_index]);
        bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index = if_index;
    }
#endif /* NX_BSD_RAW_SUPPORT */

    /* Check if the bind information is correctly set. */
    if(bsd_socket_ptr -> nx_bsd_socket_local_bind_interface == 0)
    {
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EADDRNOTAVAIL);
        
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* At this point the local bind interface and port are known. 
       If port number is specified, we need to go through the existing sockets
       and make sure there is no conflict. */
    address_conflict = 0;

    if(local_port)
    {

        for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
        {

            /* Skip its own entry. */
            if((i == sockID) ||
               /* Skip invalid entries. */
               (!(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE)) ||
               /* Skip the entries with different protocol ID */
               (nx_bsd_socket_array[i].nx_bsd_socket_protocol != bsd_socket_ptr -> nx_bsd_socket_protocol) ||
               /* Skip the unbound entries */
               (!(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_BOUND)))
            {
            
                continue;
            }

            /* Check for port number and interface ID */
            if(nx_bsd_socket_array[i].nx_bsd_socket_local_port == (USHORT)local_port)
            {

                address_conflict = 1;
            
                if((nx_bsd_socket_array[i].nx_bsd_socket_local_bind_interface == bsd_socket_ptr -> nx_bsd_socket_local_bind_interface) &&
                   (nx_bsd_socket_array[i].nx_bsd_socket_family == bsd_socket_ptr -> nx_bsd_socket_family))
                {
                    
                    /* This is completely duplicate binding.  */

                    /* If it is a TCP non-listen socket (in other words a TCP server socket that is 
                       already in connection, and the REUSEADDR is set, it is OK. */
                    if((nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED) &&
                       (!(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_CLIENT)) &&
                       (bsd_socket_ptr -> nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_REUSEADDR))
                    {

                        address_conflict = 0;
                    }
                }
                else
                {

                    /* If the REUSEADDR option is set, the socket can be bound to its specififed local address. */
                    if(bsd_socket_ptr -> nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_REUSEADDR)
                    {

                        address_conflict = 0;

                        if(bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_UDP)
                        {              

                            UINT counter;

                            /* For UDP socket, it needs to share the underlying NetX UDP socket. */
                            nx_udp_socket_delete(bsd_socket_ptr -> nx_bsd_socket_udp_socket);

                            /* Free the memory. */
                            memset((VOID*)bsd_socket_ptr -> nx_bsd_socket_udp_socket, 0, sizeof(NX_UDP_SOCKET));

                            tx_block_release((VOID*)bsd_socket_ptr -> nx_bsd_socket_udp_socket);
                            
                            /* Add this bsd udp socket to the list that map to the same NetX udp socket. */
                            
                            /* See if this is the only bsd udp socket on the list. */
                            if ((&nx_bsd_socket_array[i]) == nx_bsd_socket_array[i].nx_bsd_socket_next)
                            {

                                /* Yes, the only bsd udp socket on the list. */
                                /* Update the list. */
                                bsd_socket_ptr -> nx_bsd_socket_next = &nx_bsd_socket_array[i];
                                bsd_socket_ptr -> nx_bsd_socket_previous = &nx_bsd_socket_array[i];
                                nx_bsd_socket_array[i].nx_bsd_socket_next = bsd_socket_ptr;
                                nx_bsd_socket_array[i].nx_bsd_socket_previous = bsd_socket_ptr;
                                
                            }
                            else
                            {

                                /* At least one more bsd udp socket on this list. */
                                /* Update the list. */
                                bsd_socket_ptr -> nx_bsd_socket_next = nx_bsd_socket_array[i].nx_bsd_socket_next;
                                bsd_socket_ptr -> nx_bsd_socket_previous = &nx_bsd_socket_array[i];
                                (nx_bsd_socket_array[i].nx_bsd_socket_next) -> nx_bsd_socket_previous = bsd_socket_ptr;
                                nx_bsd_socket_array[i].nx_bsd_socket_next = bsd_socket_ptr;
                            }


                            bsd_socket_ptr -> nx_bsd_socket_udp_socket = nx_bsd_socket_array[i].nx_bsd_socket_udp_socket;
                            
                            /* Increase the counter. */
                            counter = (UINT)bsd_socket_ptr -> nx_bsd_socket_udp_socket -> nx_udp_socket_reserved_ptr;
                            counter = ((counter & 0xFFFF0000) + 0x00010000 + (counter & 0x0000FFFF)) & 0xFFFFFFFF;

                            bsd_socket_ptr -> nx_bsd_socket_udp_socket -> nx_udp_socket_reserved_ptr = (VOID*)counter;

                            bsd_socket_ptr -> nx_bsd_socket_local_port = (USHORT)local_port;
                            bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_BOUND;

                            /* Release the protection mutex.  */
                            tx_mutex_put(nx_bsd_protection_ptr);
                            
                            return(NX_SOC_OK);
                        }
                        else if(bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_TCP)
                        {

                            /* Just point this BSD TCP socket to the same secondary socket. */
                            (bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id = nx_bsd_socket_array[i].nx_bsd_socket_union_id.nx_bsd_socket_secondary_socket_id;

                            bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_BOUND;
                            
                            bsd_socket_ptr -> nx_bsd_socket_local_port = (USHORT)local_port;

                            /* Release the protection mutex.  */
                            tx_mutex_put(nx_bsd_protection_ptr);
                            
                            return(NX_SOC_OK);
                        }
                    }
                }

                if(address_conflict)
                {
                
                    break; /* Break out of the for loop */
                }
            }
        }
    }

#ifdef NX_BSD_RAW_SUPPORT
    if (localAddress -> sa_family == AF_PACKET)
    {
        for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
        {

            /* Skip its own entry. */
            if((i == sockID) ||
               /* Skip invalid entries. */
               (!(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE)) ||
               /* Skip the entries with different protocol ID */
               (nx_bsd_socket_array[i].nx_bsd_socket_protocol != bsd_socket_ptr -> nx_bsd_socket_protocol) ||
               /* Skip the entries with different address family. */
               (nx_bsd_socket_array[i].nx_bsd_socket_family != bsd_socket_ptr -> nx_bsd_socket_family) ||
               /* Skip the unbound entries */
               (!(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_BOUND)))
            {
            
                continue;
            }

            if (nx_bsd_socket_array[i].nx_bsd_socket_local_bind_interface_index == bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index)
            {

                /* Bind to same interface. */
                address_conflict = 1;
                break;
            }

            if (nx_bsd_socket_array[i].nx_bsd_socket_local_bind_interface_index == NX_BSD_LOCAL_IF_INADDR_ANY)
            {

                /* A socket is bound to any interface. */
                address_conflict = 1;
                break;
            }
        }
    }
#endif /* NX_BSD_RAW_SUPPORT */

    if(address_conflict)
    {
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
        
        /* Set the socket error if extended socket options enabled. */
        set_errno(EADDRINUSE);
        
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }
 
    /* Mark this BSD socket as busy.  */
    bsd_socket_ptr -> nx_bsd_socket_busy = tx_thread_identify();

    /* Determine what type of bind is required.  */
    if (bsd_socket_ptr -> nx_bsd_socket_tcp_socket)
    {

        /* Setup TCP socket pointer.  */
        tcp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_tcp_socket;
        
        /* Call NetX to bind the client socket.  */
        status =  nx_tcp_client_socket_bind(tcp_socket_ptr, (UINT)local_port, NX_NO_WAIT);

        /* Update the port. */
        if((status == NX_SUCCESS) && (local_port == 0))
            local_port = (INT)(tcp_socket_ptr -> nx_tcp_socket_port);

    }
    else if (bsd_socket_ptr -> nx_bsd_socket_udp_socket)
    {
    
        /* Set up a pointer to the UDP socket.  */
        udp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_udp_socket;

        /* Bind the UDP socket to the specified port in NetX.  */        
        status =  nx_udp_socket_bind(udp_socket_ptr, (UINT)local_port, NX_BSD_TIMEOUT);

        /* Update the port. */
        if((status == NX_SUCCESS) && (local_port == 0))
            local_port = (INT)(udp_socket_ptr -> nx_udp_socket_port);
    }
    else
    {

#ifdef NX_BSD_RAW_SUPPORT
        if ((localAddress -> sa_family == AF_PACKET) && (addressLength == sizeof(struct sockaddr_ll)))
        {

            /* Bind to link layer address is supported. */
            status = NX_SUCCESS;
        }
        else
#endif /* NX_BSD_RAW_SUPPORT */
        {

            /* Unsupported socket type. */
            /* Set the socket error.  */
            set_errno(EINVAL);

            /* Return an error, unsuccessful socket bind call.  */        
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);

            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            return(NX_SOC_ERROR);
        }
    }
        

    /* Check if we were able to bind the port. */
    if (status == NX_SUCCESS)
    {

        bsd_socket_ptr -> nx_bsd_socket_local_port = (USHORT)local_port;
        bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_BOUND;


        /* Make sure this thread is still the owner.  */
        if (bsd_socket_ptr -> nx_bsd_socket_busy == tx_thread_identify())
        {
    
            /* Clear the busy flag.  */
            bsd_socket_ptr -> nx_bsd_socket_busy =  TX_NULL;
        }

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
        
        /* Return successful status.  */
        return(NX_SOC_OK);

    }    
    
    /* Release the protection mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);

    /* Set the socket error, if extended socket options enabled,  depending on the status returned by NetX. */
    nx_bsd_set_error_code(bsd_socket_ptr, status);

    /* Return an error, unsuccessful socket bind call.  */        
    NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
    return(NX_SOC_ERROR);
    
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    listen                                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets the given socket ready to accept incoming client */
/*    connections. The socket must already be associated with a local port*/
/*    which means the bind() must have been called previously.            */
/*    After this call, incoming TCP connections requests addressed to the */
/*    local port (and IP address, if specified previously) will be        */
/*    completed & queued until they are passed to the program via accept()*/
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    sockID                                socket descriptor             */
/*    backlog                               Maximum number of new         */
/*                                          connections queued            */
/*                                                                        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SOC_OK (0)                         If success                    */
/*    NX_SOC_ERROR (-1)                     If failure.                   */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    socket                                Create a server socket        */
/*    nx_tcp_server_socket_listen           Enable a server socket listen */
/*    tx_mutex_get                          Get protection                */
/*    tx_mutex_put                          Release protection            */
/*                                                                        */
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
INT  listen(INT sockID, INT backlog)
{

UINT                status;
NX_BSD_SOCKET      *bsd_socket_ptr;
NX_BSD_SOCKET      *bsd_secondary_socket;
INT                 secondary_sockID;
INT                 ret;


    /* Check whether supplied socket ID is valid.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EBADF);

        /* Return an error. */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;
    
    /* Get the protection mutex.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status)
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);

        /* Return an error. */
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Set up a pointer to the BSD socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    /* Determine if the socket is a UDP socket.  */
    if (bsd_socket_ptr -> nx_bsd_socket_protocol != NX_PROTOCOL_TCP)
    {
    
        /* The underlying protocol is not TCP, therefore it does not support the listen operation. */
        set_errno(EOPNOTSUPP);
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
        
        /* Return an error code.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }    

    /* Is the socket still in use?  */
    if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EBADF);  
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
        
        /* Return error code.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }        

    /* Check if the socket has an error */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR) 
    {                                                                        
        INT errcode = bsd_socket_ptr -> nx_bsd_socket_error_code;    

        /* Now clear the error code. */
        bsd_socket_ptr -> nx_bsd_socket_error_code = 0;
        
        /* Clear the error flag.  The application is expected to close the socket at this point.*/  
        bsd_socket_ptr -> nx_bsd_socket_status_flags = 
            bsd_socket_ptr -> nx_bsd_socket_status_flags & (ULONG)(~NX_BSD_SOCKET_ERROR); 
                                                                             
        set_errno(errcode);                                                  
                                                                             
        /* Release the protection mutex.  */                                  
        tx_mutex_put(nx_bsd_protection_ptr);                                     
                                                                              
        /* Return an error.  */                                               
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);                                 
                                                                              
        /* At this point the error flag is cleared.  Application should       
           detect and handle the error codition. This socket is still bound   
           to the port (either the application called bind(), or a bind       
           operation was executed as part of the connect call) is able to     
           handle another "connect" call, or be closed. */                    
        return(NX_SOC_ERROR);                                                 
    }                                                                            
        
    /* Have we already started listening?  */
    if (bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ENABLE_LISTEN)
    {

        /* Error, socket is already listening.  */
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        /* Return error code.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Check if this is a secondary server socket.  */
    if (bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_SECONDARY_SOCKET)
    {
 
        /* Error, socket is a secondary server socket.  */
          
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EOPNOTSUPP);  

        /* Return error code.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Check if bound to a port.  */
    if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_BOUND))
    {

       /* Release the protection mutex.  */
       tx_mutex_put(nx_bsd_protection_ptr);

       /* Set the socket error code. */
       set_errno(EDESTADDRREQ);  

       /* Return error code.  */
       NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
       return(NX_SOC_ERROR);
    }

    /* Check if this master (listening) socket's secondary socket is not marked invalid.  If not, it means this socket will
       share the secondary socket with another master socket. */
    if((bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id != NX_BSD_MAX_SOCKETS)
    {

        /* It is set. */
        
        secondary_sockID = (bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id;

        bsd_secondary_socket = &nx_bsd_socket_array[secondary_sockID];

        /* Now check if the other master socket is in listen mode. */
        if(bsd_secondary_socket -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ENABLE_LISTEN)
        {

            /* It  is ready.. we are ready to listen on this socket. */

            bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_ENABLE_LISTEN;
            bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_SERVER_SECONDARY_SOCKET);
            bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_client_type =  NX_FALSE;
            bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_SERVER_MASTER_SOCKET;            

            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            return(NX_SOC_OK);
        }
    }

    if(backlog < NX_BSD_TCP_LISTEN_MIN_BACKLOG)
    {
        backlog = NX_BSD_TCP_LISTEN_MIN_BACKLOG;
    }

    /* We need to set up this socket as a listen socket. */
    ret = nx_bsd_tcp_create_listen_socket(sockID, backlog);

    /* Release the mutex protection.  */
    tx_mutex_put(nx_bsd_protection_ptr);

    /* Return success.  */
    return(ret);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    accept                                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function blocks while waiting for connections addressed to the */
/*    IP address and port to which this socket is bound. A listen() must  */
/*    previously have been called on this given socket.                   */
/*                                                                        */
/*    When a connection arrives and the TCP handshake is successfully     */
/*    completed, this function returns with a new socket with local and   */
/*    remote address and port numbers filled in.                          */
/*                                                                        */
/*    For non blocking sockets, this function returns immediately.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*     sockID                               socket descriptor             */
/*     clientAddress                        Originating socket IP address */
/*                                          and port.                     */
/*     addressLength                        Length of sockaddr buffer (in)*/
/*                                          returned address (out)        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    socket id                             Socket ID for new connection  */
/*    NX_SOC_ERROR (-1)                     If failure                    */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                                Clears memory                 */
/*    socket                                Create a server socket        */
/*    nx_tcp_server_socket_relisten         Relisten with a new TCP soc   */
/*    nx_tcp_server_socket_accept           Accept a client connection    */
/*    tx_mutex_get                          Get protection                */
/*    tx_mutex_put                          Release protection            */
/*    tx_thread_identify                    Gets the current thread       */
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
/*  09-30-2020     Yuxin Zhou               Modified comment(s), and      */
/*                                            verified memcpy use cases,  */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
INT  accept(INT sockID, struct sockaddr *ClientAddress, INT *addressLength)
{
/* Define the accept function if NetX BSD accept() is not set to asynchronous (on automatic callback). */

UINT                status;
NX_BSD_SOCKET       *bsd_socket_ptr;
NX_BSD_SOCKET       *bsd_secondary_socket;
INT                 sec_sock_id;
INT                 ret = 0;
INT                 connected = 0;
ULONG               requested_events;
INT                 secondary_socket_id = 0;
struct sockaddr_in  peer4_address;


    /* Check for valid socket ID.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EBADF);  

        /* Return an error.*/
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;

    /* Setup pointer to the BSD socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    /* Get the protection mutex.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);  

        /* Return an error.*/
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Is the socket still in use?  */
    if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
    {
       
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EBADF);  

        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }        

    /* If the socket has an error */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR) 
    {            

        INT errcode = bsd_socket_ptr -> nx_bsd_socket_error_code;    

        /* Now clear the error code. */
        bsd_socket_ptr -> nx_bsd_socket_error_code = 0;
        
        /* Clear the error flag.  The application is expected to close the socket at this point.*/  
        bsd_socket_ptr -> nx_bsd_socket_status_flags = 
            bsd_socket_ptr -> nx_bsd_socket_status_flags & (ULONG)(~NX_BSD_SOCKET_ERROR); 
                                                                             
        set_errno(errcode);                                                  
                                                                             
        /* Release the protection mutex.  */                                  
        tx_mutex_put(nx_bsd_protection_ptr);                                     
                                                                              
        /* Return an error.  */                                               
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);                                 
                                                                              
        /* At this point the error flag is cleared.  Application should       
           detect and handle the error codition. This socket is still bound   
           to the port (either the application called bind(), or a bind       
           operation was executed as part of the connect call) is able to     

           handle another "connect" call, or be closed. */                    
        return(NX_SOC_ERROR);                                                 
    }                                                                            

    /* Determine if the socket is a UDP socket.  */
    if (bsd_socket_ptr -> nx_bsd_socket_protocol != NX_PROTOCOL_TCP)
    {
    
        /* Error, UDP sockets do not perform listen.  */

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EOPNOTSUPP);  

        /* Return error code.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }    

    /* Has listening been enabled on this socket?  */
    if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ENABLE_LISTEN))
    {

        /* No, this socket is not ready to accept TCP connections. */

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        /* Return error code.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Make sure the accept call operates on the master socket. */
    if((bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_MASTER_SOCKET) == 0)
    {
        /* This is not a master socket. 
           BSD accept is only allowed on the master socket. 
           Return. */
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EBADF);  

        /* Return error code.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Validate the secondary server socket.  */
    if ((bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id >= NX_BSD_MAX_SOCKETS)
    {

        /* This secondary socket is not available yet.  This could happen if the
           previous accept call fails to allocate a new secondary socket. */
        ret = nx_bsd_tcp_create_listen_socket(sockID, 0);

        if(ret < 0)
        {

            /* Failed to allocate a secondary socket, release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            /* Errno is already set inside nx_bsd_tcp_create_listen_socket.  Therefore 
               there is no need to set errno here. */

            /* Return an error. */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR);
        }
    }

    /* At this point, we have found and marked a secondary server socket for the connection request.  */

    /* Set up a pointer to the secondary server socket.  */
    sec_sock_id = (bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id;
    bsd_secondary_socket =  &nx_bsd_socket_array[sec_sock_id];

    /* Mark this BSD socket as busy.  */
    bsd_socket_ptr -> nx_bsd_socket_busy = tx_thread_identify();

    /* If the master socket is marked as non-blocking, we just need to check if the 
       secondary socket has a connection already. */
    while(!connected)
    {

        secondary_socket_id = (bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id;

        if((secondary_socket_id < NX_BSD_MAX_SOCKETS) &&
           (nx_bsd_socket_array[secondary_socket_id].nx_bsd_socket_union_id.nx_bsd_socket_master_socket_id == sockID) &&
           (nx_bsd_socket_array[secondary_socket_id].nx_bsd_socket_status_flags & (NX_BSD_SOCKET_CONNECTED | NX_BSD_SOCKET_ERROR)))
        {

            connected = 1;
            bsd_secondary_socket = &nx_bsd_socket_array[secondary_socket_id];
            bsd_secondary_socket -> nx_bsd_socket_family = bsd_socket_ptr -> nx_bsd_socket_family;
            bsd_secondary_socket -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTION_INPROGRESS);

        }
        else
        {

            if(bsd_socket_ptr -> nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING)
            {

                /* No connection yet. Return EWOULDBLOCK */

                tx_mutex_put(nx_bsd_protection_ptr);
                
                /* Set the socket error if extended socket options enabled. */
                set_errno(EWOULDBLOCK);  
                
                /* Return an error. */
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            
                if (bsd_socket_ptr -> nx_bsd_socket_busy == tx_thread_identify())
                {
                    bsd_socket_ptr -> nx_bsd_socket_busy = NX_NULL;
                }
                return(NX_SOC_ERROR);
            }   

            tx_mutex_put(nx_bsd_protection_ptr);
            tx_event_flags_get(&nx_bsd_events, NX_BSD_RECEIVE_EVENT, TX_OR_CLEAR, &requested_events, TX_WAIT_FOREVER);
            tx_mutex_get(nx_bsd_protection_ptr, TX_WAIT_FOREVER);

            /* Verify the socket is still valid. */
            if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
            {
                /* The socket is no longer in use. */

                /* Set the socket error code. */
                set_errno(EBADF);
                
                /* Release the protection mutex.  */
                tx_mutex_put(nx_bsd_protection_ptr);

                /* Return error code.  */
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return(NX_SOC_ERROR);
            }
        }
    }
            
    /* If we get here, we should have a valid connection, or an error occured. */
    if(bsd_secondary_socket -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR)
    {
        INT errcode = bsd_secondary_socket -> nx_bsd_socket_error_code;
        
        /* Now clear the error code. */
        bsd_secondary_socket -> nx_bsd_socket_error_code = 0;
        
        /* Clear the error flag.  The application is expected to close the socket at this point.*/  
        bsd_secondary_socket -> nx_bsd_socket_status_flags = 
            bsd_secondary_socket -> nx_bsd_socket_status_flags & (ULONG)(~NX_BSD_SOCKET_ERROR); 
                                                                             
        set_errno(errcode);                                                  
                                                                             
        /* Return an error.  */                                               
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);                                 

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
                                                                              
        /* At this point the error flag is cleared.  Application should       
           detect and handle the error codition. This socket is still bound   
           to the port (either the application called bind(), or a bind       
           operation was executed as part of the connect call) is able to     
           handle another "connect" call, or be closed. */                    
        return(NX_SOC_ERROR);                                                 
    }                                                                                    

    /* Update the BSD socket source port and sender IP address. */
    status = nx_tcp_socket_peer_info_get(bsd_secondary_socket -> nx_bsd_socket_tcp_socket, 
                                         &bsd_secondary_socket -> nx_bsd_socket_source_ip_address, 
                                         (ULONG *)(&bsd_secondary_socket -> nx_bsd_socket_source_port));

    bsd_secondary_socket -> nx_bsd_socket_peer_ip = bsd_secondary_socket -> nx_bsd_socket_source_ip_address;

    bsd_secondary_socket -> nx_bsd_socket_peer_port = (USHORT)(bsd_secondary_socket -> nx_bsd_socket_source_port);

    /* Record the peer information. */
    if(bsd_socket_ptr -> nx_bsd_socket_family == AF_INET)
    {

        bsd_secondary_socket -> nx_bsd_socket_source_ip_address = 
                bsd_secondary_socket -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_connect_ip;
    }

    /* Attempt to obtain peer address if ClientAddress is not NULL. */
    if(ClientAddress && addressLength != 0)
    {

        /* Handle the IPv4 socket type. */
        if(bsd_socket_ptr -> nx_bsd_socket_family == AF_INET)
        {

            /* Update the Client address with socket family, remote host IPv4 address and port.  */
            peer4_address.sin_family =      AF_INET;
            peer4_address.sin_addr.s_addr = ntohl(bsd_secondary_socket -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_connect_ip);
            peer4_address.sin_port =        ntohs((USHORT)bsd_secondary_socket -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_connect_port);
         
            /* Copy the peer address/port info to the ClientAddress.  Truncate if
               addressLength is smaller than the size of struct sockaddr_in */
            if(*addressLength > (INT)sizeof(struct sockaddr_in))
            {

                memcpy(ClientAddress, &peer4_address, sizeof(struct sockaddr_in)); /* Use case of memcpy is verified. */
                *addressLength = sizeof(struct sockaddr_in);
            }
            else
            {
                memcpy(ClientAddress, &peer4_address, (UINT)(*addressLength)); /* Use case of memcpy is verified. */
            }
        }
        else

        {
            
            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);
            
            /* Set the socket error if extended socket options enabled. */
            set_errno(EINVAL);  

            /* Make sure this thread is still the owner.  */
            if (bsd_socket_ptr -> nx_bsd_socket_busy == tx_thread_identify())
            {
                
                /* Clear the busy flag.  */
                bsd_socket_ptr -> nx_bsd_socket_busy =  TX_NULL;
            }

            /* Error, IPv6 support is not enabled.  */
            NX_BSD_ERROR(ERROR, __LINE__);
            return(ERROR);
        }
    }

    /* Mark the sock_id field in both the master and secondary socket invalid. */
    (bsd_secondary_socket -> nx_bsd_socket_union_id).nx_bsd_socket_master_socket_id = NX_BSD_MAX_SOCKETS;

    /* Clear the master socket connect flags. */
    bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTED);
    bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTION_REQUEST);

    /* Reset the master_socket_id */
    ret = nx_bsd_tcp_create_listen_socket(sockID, 0);

    if(ret < 0)
    {
        (bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id = NX_BSD_MAX_SOCKETS;
    }

    /* Make sure this thread is still the owner.  */
    if (bsd_socket_ptr -> nx_bsd_socket_busy == tx_thread_identify())
    {
        
        /* Clear the busy flag.  */
        bsd_socket_ptr -> nx_bsd_socket_busy =  TX_NULL;
    }

    /* Release the protection mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);

    return(secondary_socket_id + NX_BSD_SOCKFD_START);

}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_bsd_send_internal                                PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This is sends a message to a given destination address/port         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    sockID                                BSD Socket ID                 */
/*    msg                                   Pointer to the outgoing       */
/*                                            message                     */
/*    msgLength                             The Size of the message       */
/*    flags                                 Control flags, support        */
/*                                            MSG_DONTWAIT                */
/*    dst_address                           The Destination Address       */
/*    dst_port                              The Destination Port          */
/*    local_inteterface_index               The local outgoing interface  */
/*                                            to use                      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    data_sent                                                           */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    set_errno                             Sets the BSD errno            */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nx_packet_data_append                 Append data to the packet     */
/*    tx_mutex_get                          Get Mutex protction           */
/*    tx_mutex_put                          Release Mutex protection      */
/*    nx_packet_release                     Release the packet on error   */
/*    nx_udp_socket_send                    UDP packet send               */
/*    nx_udp_socket_interface_send          UDP packet send via a         */
/*                                            specific interface          */
/*    nx_tcp_socket_send                    TCP packet send               */
/*  CALLED BY                                                             */
/*                                                                        */
/*    send                                                                */
/*    sendto                                                              */
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
static INT nx_bsd_send_internal(INT sockID, const CHAR *msg, INT msgLength, INT flags,
                                ULONG dst_address, USHORT dst_port, UINT local_interface_index)
{
UINT                status;
NX_PACKET           *packet_ptr;
NX_TCP_SOCKET       *tcp_socket_ptr;
NX_UDP_SOCKET       *udp_socket_ptr;
NX_BSD_SOCKET       *bsd_socket_ptr;
UINT                packet_type = 0;
UINT                wait_option;
ULONG               data_sent = (ULONG)msgLength;

    bsd_socket_ptr = &nx_bsd_socket_array[sockID];
        
    /* Determine the socket family for allocating a packet. */
    if (bsd_socket_ptr -> nx_bsd_socket_family == AF_INET)
    {

        /* This is for an IPv4 socket.   */
        if (bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_UDP)
        {

            /* Allocate an IPv4 UDP packet.   */
            packet_type = NX_UDP_PACKET;
        }
        else if(bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_TCP)
        {

            /* Allocate an IPv4 TCP packet.   */
            packet_type = NX_TCP_PACKET;
        }
        else if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_TX_HDR_INCLUDE)
        {

            packet_type = NX_PHYSICAL_HEADER;
        }
        else
        {

            /* Unsupported socket type. */
            packet_type = 0;
        }
    }

    /* Allocate the packet for sending.  */
    if(packet_type == 0)
    {
        /* Set the socket error.  */
        set_errno(EINVAL);

        /* Return an error status.*/
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Is this a non blocking socket? */
    if ((bsd_socket_ptr -> nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING) ||
        (flags & MSG_DONTWAIT))
    {

        /* Yes, set to wait to zero on the NetX call. */
        wait_option = 0 ; 
    }
    /* Does this socket have a send timeout option set? */
    else if (bsd_socket_ptr -> nx_bsd_option_send_timeout)
    {
         
        /* Yes, this is our wait option. */
        wait_option = bsd_socket_ptr -> nx_bsd_option_send_timeout; 
    }
    else
        wait_option = TX_WAIT_FOREVER;
    
    status =  nx_packet_allocate(nx_bsd_default_packet_pool, &packet_ptr, packet_type, wait_option);
    
    /* Check for errors.   */
    if (status != NX_SUCCESS)
    {

        /* Set the socket error.  */
        set_errno(ENOBUFS);

        /* Return an error status.*/
        NX_BSD_ERROR(status, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Now copy the data into the NetX packet.  */
    status =  nx_packet_data_append(packet_ptr, (VOID *) msg, (ULONG)msgLength, nx_bsd_default_packet_pool, wait_option);

    /* Was the data copy successful?  */
    if (status != NX_SUCCESS)
    {

        nx_packet_release(packet_ptr);

        /* Set the socket error.  */
        set_errno(ENOBUFS);

        /* Return an error status.*/
        NX_BSD_ERROR(status, __LINE__);
        return(NX_SOC_ERROR);
    }
    

    /* Get the protection mutex.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        /* Release the packet.  */
        nx_packet_release(packet_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);  

        /* Return an error status.*/
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }


    /* Is the socket still in use?  */
    if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
    {

        nx_packet_release(packet_ptr);

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
        
        /* Return an error status.*/
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }        


    /* Determine if the socket is a UDP socket.  */
    if (bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_UDP)
    {
    
         /* Pickup the NetX UDP socket.  */
         udp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_udp_socket;

         /* Send the UDP packet.  */
         if(local_interface_index == NX_BSD_LOCAL_IF_INADDR_ANY)
             status =  nx_udp_socket_send(udp_socket_ptr, packet_ptr, dst_address, dst_port);
         else
             status =  nx_udp_socket_interface_send(udp_socket_ptr, packet_ptr, dst_address, dst_port, local_interface_index);
    }   
    else if(bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_TCP)  
    {

        /* We have a TCP socket and a packet ready to send.  */
    
        /* Set a pointer to the TCP BSD socket.  */
        tcp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_tcp_socket;
    
        if(wait_option != TX_NO_WAIT)
        {
            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);
        }

        /* Send the TCP packet.  */
        status =  nx_tcp_socket_send(tcp_socket_ptr, packet_ptr, wait_option);

        /* Check partial data sent. */
        if (status)
        {

            /* Get length of data sent. */
            data_sent -= packet_ptr -> nx_packet_length;

            if (data_sent)
            {

                /* Partial data sent. Mark as success. */
                status = NX_SUCCESS;

                /* Release the packet.  */
                nx_packet_release(packet_ptr);
            }
        }

        if(wait_option != TX_NO_WAIT)
        {
            /* Obtain the protection mutex.  */
            tx_mutex_get(nx_bsd_protection_ptr, TX_WAIT_FOREVER);
        }
    }

    /* Was the packet send successful?  */
    if (status != NX_SUCCESS)
    { 

        /* No, release the packet.  */
        nx_packet_release(packet_ptr);

        /* Set the socket error.  */

        /* Set the socket error according to the NetX error status returned.  */
        switch (status)
        {

            case NX_IP_ADDRESS_ERROR:
                set_errno(EDESTADDRREQ);
                break;

            case NX_NOT_ENABLED:
                set_errno(EPROTONOSUPPORT);
                break;

            case NX_NOT_CONNECTED:
                set_errno(ENOTCONN);
                break;

            case NX_NO_PACKET:
            case NX_UNDERFLOW:
                set_errno(ENOBUFS);
                break;

            case NX_WINDOW_OVERFLOW:
            case NX_WAIT_ABORTED:
            case NX_TX_QUEUE_DEPTH:
                if ((bsd_socket_ptr -> nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING) ||
                    (flags & MSG_DONTWAIT))
                    set_errno( EWOULDBLOCK);
                else
                    set_errno(ETIMEDOUT);
                break;

            default:
                /* NX_NOT_BOUND */
                /* NX_PTR_ERROR */
                /* NX_INVALID_PACKET */
                set_errno(EINVAL);  
                break;
        }

        /* Return an error status. */
        NX_BSD_ERROR(status, __LINE__);

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        return(NX_SOC_ERROR);
    }    

    /* Release the protection mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);

    return((INT)data_sent);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    send                                                PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a packet out the given  socket.                 */
/*    When the call returns, the data has been queued for transmission    */
/*    over the connection. The return value indicates the number of byes  */
/*    actually transmitted.                                               */
/*                                                                        */
/*    The flags argument is provided for consistency with the BSD send    */
/*    service. It allows various protocol features, such as out-of-bound  */
/*    out-of-bound data, to be accessed. However, none of these features  */
/*    are implemented.                                                    */
/*                                                                        */
/*    If packets are being sent out a UDP socket which is not bound to a  */
/*    local port, this function find an available free port to bind to the*/
/*    socket. For TCP sockets, the socket must already by connected (so   */
/*    also bound to port)                                                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    sockID                                Socket                        */
/*    msg                                   Data to be transmitted        */
/*    msgLength                             Number of bytes to be sent    */
/*    flags                                 Control flags, support        */
/*                                            MSG_DONTWAIT                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*     number of bytes sent                 If successful                 */
/*     NX_SOC_ERROR (-1)                    If failure                    */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*   nx_tcp_socket_send                     Send a packet                 */
/*   nx_packet_allocate                     Get a free packet             */
/*   nx_packet_data_append                  Copy data into packet         */
/*   nx_packet_release                      Free a packet used to send    */
/*   tx_mutex_get                           Get protection                */
/*   tx_mutex_put                           Release protection            */
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
INT  send(INT sockID, const CHAR *msg, INT msgLength, INT flags)
{

NX_BSD_SOCKET *bsd_socket_ptr;


    /* Check for invalid socket IDd.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);

        /* Return an error status.*/
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;

    /* Set up a pointer to the BSD socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    /* If the socket has an error */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR) 
    {                                                                        
        INT errcode = bsd_socket_ptr -> nx_bsd_socket_error_code;    

        /* Now clear the error code. */
        bsd_socket_ptr -> nx_bsd_socket_error_code = 0;
        
        /* Clear the error flag.  The application is expected to close the socket at this point.*/  
        bsd_socket_ptr -> nx_bsd_socket_status_flags = 
            bsd_socket_ptr -> nx_bsd_socket_status_flags & (ULONG)(~NX_BSD_SOCKET_ERROR); 
                                                                             
        set_errno(errcode);                                                  
                                                                             
        /* Return an error.  */                                               
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);                                 
                                                                              
        /* At this point the error flag is cleared.  Application should       
           detect and handle the error codition. This socket is still bound   
           to the port (either the application called bind(), or a bind       
           operation was executed as part of the connect call) is able to     
           handle another "connect" call, or be closed. */                    
        return(NX_SOC_ERROR);                                                 
    }                                                                            

    /* Send() requires the socket be connected. A connected socket implies the socket is bound.*/
    if((bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED) == 0)
    {

        /* Set the socket error */
        set_errno(ENOTCONN);

        /* Return an error status.*/
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    return nx_bsd_send_internal(sockID, msg, msgLength, flags,
                                bsd_socket_ptr -> nx_bsd_socket_peer_ip, 
                                bsd_socket_ptr -> nx_bsd_socket_peer_port,
                                bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index);
    
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    sendto                                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a packet out the given socket.                  */
/*    When the call returns, the data has been queued for transmission    */
/*    over the connection. To use sendto on a TCP BSD socket, the         */
/*    socket must already be in connected state.                          */
/*                                                                        */
/*    The flags argument is provided for consistency with the BSD send    */
/*    service. It allows various protocol features, such as out-of-bound  */
/*    out-of-bound data, to be accessed. However, none of these features  */
/*    are implemented.                                                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    sockID                                Socket (must be connected).   */
/*    msg                                   Data to transmit.             */
/*    msgLength                             Number of bytes to send       */
/*    flags                                 Control flags, support        */
/*                                            MSG_DONTWAIT                */
/*    sockaddr                              Destination address           */
/*    destAddrLen                           Length of destination address */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    Number of bytes sent                  If no error occurs            */
/*    NX_SOC_ERROR (-1)                     In case of socket error       */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    bind                                 Bind NetX UDP sockets          */
/*    nx_packet_allocate                   Get a free packet              */
/*    nx_packet_data_append                Copy data into packet          */
/*    nx_packet_release                    Free the nx_packet used        */
/*    nx_tcp_socket_send                   Send packet over a TCP Socket  */
/*    nx_udp_socket_send                   Send packet over a UDP Socket  */
/*    tx_mutex_get                         Get protection                 */
/*    tx_mutex_put                         Release protection             */
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
INT  sendto(INT sockID, CHAR *msg, INT msgLength, INT flags,  struct sockaddr *destAddr, INT destAddrLen)
{
UINT                 status;
NX_BSD_SOCKET       *bsd_socket_ptr;
ULONG                peer_ip_address = 0;
USHORT               peer_port = 0;

    /* Check for a valid socket ID.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);

        /* Return an error status. */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Set up a socket pointer to the BSD socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID - NX_BSD_SOCKFD_START];

    /* If the socket has an error */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR) 
    {                                                                        
        INT errcode = bsd_socket_ptr -> nx_bsd_socket_error_code;    

        /* Now clear the error code. */
        bsd_socket_ptr -> nx_bsd_socket_error_code = 0;
        
        /* Clear the error flag.  The application is expected to close the socket at this point.*/  
        bsd_socket_ptr -> nx_bsd_socket_status_flags = 
            bsd_socket_ptr -> nx_bsd_socket_status_flags & (ULONG)(~NX_BSD_SOCKET_ERROR); 
                                                                             
        set_errno(errcode);                                                  
                                                                             
        /* Return an error.  */                                               
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);                                 
                                                                              
        /* At this point the error flag is cleared.  Application should       
           detect and handle the error codition. This socket is still bound   
           to the port (either the application called bind(), or a bind       
           operation was executed as part of the connect call) is able to     
           handle another "connect" call, or be closed. */                    
        return(NX_SOC_ERROR);                                                 
    } 
    /* For TCP, make sure the socket is already connected. */
    if(bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_TCP)
    {
        if((bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED) == 0)
        {
            set_errno(ENOTCONN);
            
            /* Return an error.  */                                               
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);                                 
            
            return(NX_SOC_ERROR);
        }
        return nx_bsd_send_internal((sockID - NX_BSD_SOCKFD_START), msg, msgLength, flags, NX_NULL, 0, 
                                    bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index);
    }
    else 
    {

        /* This is a UDP socket.  */

        /* Check whther or not the socket is AF_PACKET family. */
        if(bsd_socket_ptr -> nx_bsd_socket_family == AF_PACKET)
        {

#if   defined(NX_BSD_RAW_SUPPORT)
            /* _nx_bsd_hardware_internal_sendto shall returns */
            status = (UINT)_nx_bsd_hardware_internal_sendto(bsd_socket_ptr, msg, msgLength, flags,  destAddr, destAddrLen);
#else
            NX_PARAMETER_NOT_USED(destAddrLen);
            status = (UINT)NX_SOC_ERROR;
#endif /* NX_BSD_RAW_PPPOE_SUPPORT */
            return((INT)status);

        }

        /* Check for an invalid destination. */
        if (destAddr == NX_NULL)
        {
        
            /* Set the socket error if extended socket options enabled. */
            set_errno(EINVAL);  
            
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR);
        }

        /* Validate the destination address. */
        if(bsd_socket_ptr -> nx_bsd_socket_family != destAddr -> sa_family)
        {
            set_errno(EAFNOSUPPORT);
            
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            
            return(NX_SOC_ERROR);
        }

        /* For UDP socket, make sure the socket is bound. */
        if(bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_UDP)
        {
            if(!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_BOUND))
            {
                status = nx_udp_socket_bind(bsd_socket_ptr -> nx_bsd_socket_udp_socket, NX_ANY_PORT, NX_NO_WAIT);
                if((status != NX_SUCCESS) && (status != NX_ALREADY_BOUND))
                {
                    set_errno(EINVAL);

                    NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);

                    return(NX_SOC_ERROR);
                }

                bsd_socket_ptr -> nx_bsd_socket_local_bind_interface = NX_BSD_LOCAL_IF_INADDR_ANY;
                bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index = NX_BSD_LOCAL_IF_INADDR_ANY;
                bsd_socket_ptr -> nx_bsd_socket_local_port = (USHORT)(bsd_socket_ptr -> nx_bsd_socket_udp_socket -> nx_udp_socket_port);
                bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_BOUND;
            }

        }



        {
            /* Get the destination IP and port for this UDP socket.  */
            if (bsd_socket_ptr -> nx_bsd_socket_family == AF_INET)
            {

                /* This is for an IPv4 packet. */
                peer_ip_address = htonl(((struct sockaddr_in *) destAddr) -> sin_addr.s_addr);
                peer_port = htons(((struct sockaddr_in *) destAddr) -> sin_port);

                /* Local interface ID is set to invalid value, so the send routine needs to 
                   find the best interface to send the packet based on destination IP address. */

            }
        }

        /* Call the internal send routine to finish the send process. */
        /* Local interface ID is set to a special marker, so the send routine needs to 
           find the best interface to send the packet based on destination IP address. */
        return nx_bsd_send_internal((sockID - NX_BSD_SOCKFD_START), msg, msgLength, flags,
                                    peer_ip_address, peer_port, 
                                    bsd_socket_ptr -> nx_bsd_socket_local_bind_interface_index);

    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    recv                                                PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function copies up to a specified number of bytes received on  */
/*    the socket into specified location. The given socket must be in the */
/*    connected state. Normally, the call blocks until either at least one*/
/*    byte is returned or the connection closes.The return value indicates*/
/*    the number of bytes actually copied into the buffer starting at the */
/*    specified location.                                                 */
/*                                                                        */ 
/*    For a stream socket, the bytes are delivered in the same order as   */
/*    they were transmitted, without omissions. For a datagram socket,    */
/*    each recv() returns the data from at most one send(), and order is  */
/*    not necessarily preserved.                                          */
/*                                                                        */ 
/*    For non blocking sockets, a receive status of NX_NO_PACKET from NetX*/
/*    results in an error status returned from BSD, and the socket error  */
/*    set to EWOULDBLOCK (if BSD extended socket features are enabled.    */
/*                                                                        */ 
/*    Likewise, an event flag status of TX_NO_EVENTS returned from ThreadX*/
/*    on a non blocking socket sets the socket error to EWOULDBLOCK.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    sockID                                Socket (must be connected).   */
/*    rcvBuffer                             Pointer to put data received. */
/*    bufferLength                          Maximum bytes in buffer       */
/*    flags                                 Control flags, support        */
/*                                            MSG_PEEK and MSG_DONTWAIT   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    Number of bytes received              If success                    */
/*    NX_SOC_ERROR (-1)                     If failure                    */
/*    0                                     socket disconnected           */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_tcp_socket_receive                 Receive a Packet              */
/*    nx_packet_allocate                    Allocate packet for receive   */
/*    nx_packet_release                     Free the nx_packet after use  */
/*    nx_packet_data_extract_offset         Retrieve packet data          */
/*    tx_event_flags_get                    Wait for data to arrive       */
/*    tx_mutex_get                          Get protection                */
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
/*  09-30-2020     Yuxin Zhou               Modified comment(s), and      */
/*                                            verified memcpy use cases,  */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
INT  recv(INT sockID, VOID *rcvBuffer, INT bufferLength, INT flags)
{

UINT                status;
NX_PACKET           *packet_ptr;
NX_BSD_SOCKET       *bsd_socket_ptr;
NX_TCP_SOCKET       *tcp_socket_ptr;
ULONG               requested_events;
ULONG               bytes_received;
UINT                wait_option;
UINT                remaining_wait_option;
ULONG               offset;
INT                 header_size = 0;
ULONG               start_time = nx_bsd_system_clock;


    /* Check for a valid socket ID.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);

        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);

        return(NX_SOC_ERROR);
    }

    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;

    /* Set up a pointer to the socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    /* Set the receive wait time to FOREVER for blocking sockets. */
    wait_option = NX_WAIT_FOREVER;

    /* Is this a nonblocking socket?:  */
    if ((bsd_socket_ptr -> nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING) || 
        (flags & MSG_DONTWAIT))
    {

        /* Yes, set to receive wait option to no wait (zero). */
        wait_option = 0; 
    }
    /* Does this socket have a receive timeout option set? */
    else if (bsd_socket_ptr -> nx_bsd_option_receive_timeout)
    {
         
        /* Yes, this is our wait option. */
        wait_option = bsd_socket_ptr -> nx_bsd_option_receive_timeout; 
    }

    /* Get the protection mutex.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status)
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);  

        /* Return an error. */
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* If the socket has an error */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR) 
    {                    

        INT errcode = bsd_socket_ptr -> nx_bsd_socket_error_code;    

        /* Now clear the error code. */
        bsd_socket_ptr -> nx_bsd_socket_error_code = 0;
        
        /* Clear the error flag.  The application is expected to close the socket at this point.*/  
        bsd_socket_ptr -> nx_bsd_socket_status_flags = 
            bsd_socket_ptr -> nx_bsd_socket_status_flags & (ULONG)(~NX_BSD_SOCKET_ERROR); 
                                                                             
        set_errno(errcode);                                                  

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);     

        /* Return an error.  */                                               
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);                                 
                                                                              
        /* At this point the error flag is cleared.  The application should       
           detect and handle the error codition. This socket is still bound   
           to the port (either the application called bind(), or a bind       
           operation was executed as part of the connect call) and is able to     
           handle another "connect" call, or be closed. */                    
        return(NX_SOC_ERROR);                                                 
    }                                                                            

    /* Set pointers to the BSD NetX sockets.  */
    tcp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_tcp_socket;

    /* Loop to check for a received packet.  */
    do
    {

        /* Is the socket still in use?  */
        if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
        {

            /* Set the socket error if extended options enabled. */
            set_errno(EBADF);

            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);
        
            /* Return an error.  */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR);
        }        

        /* Check if the BSD socket already has received a packet.  */
        packet_ptr =  bsd_socket_ptr -> nx_bsd_socket_received_packet;

        if (packet_ptr)
        {

            /* Got one. Break out of the loop.  */
            break;
        }

        /* Check if there is an incoming packet on this socket.  */
        else
        {
        
            /* Determine if this is a TCP BSD socket.  */
            if (tcp_socket_ptr)
            {
            
                /* It is, check the socket TCP receive queue with a zero wait option (no suspension).  */
                status =  nx_tcp_socket_receive(tcp_socket_ptr, &packet_ptr, TX_NO_WAIT);
                
                /* Check for no packet on the queue.  */
                if (status == NX_NOT_CONNECTED)
                {

                    /* Release the protection mutex.  */
                    tx_mutex_put(nx_bsd_protection_ptr);

                    /* Is peer shutdown orderly? */
                    if ((tcp_socket_ptr -> nx_tcp_socket_state == NX_TCP_CLOSE_WAIT) ||
                        (tcp_socket_ptr -> nx_tcp_socket_state >= NX_TCP_CLOSING))
                    {

                        /* Yes. Return 0. */
                        return(NX_SUCCESS);
                    }

                    /* Set the socket status (not really an error).  */
                    set_errno(ENOTCONN); 
        
                    /* Return an error.  */
                    NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                    return(NX_SOC_ERROR);        
                }

                if (status == NX_SUCCESS)
                {

                    /* Increase the received count. */
                    bsd_socket_ptr -> nx_bsd_socket_received_byte_count += packet_ptr -> nx_packet_length;
                    bsd_socket_ptr -> nx_bsd_socket_received_packet_count++;
                }
            }

            /* Have we found a new packet?  */
            if ((status == NX_SUCCESS) && (packet_ptr))
            {

                /* Setup the bsd socket with the packet information.  */
                bsd_socket_ptr -> nx_bsd_socket_received_packet =         packet_ptr;
                bsd_socket_ptr -> nx_bsd_socket_received_packet_offset =  0;
                
                /* Get out of the loop.  */
                break;
            }
        }

        /* No packet is available.  */

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Calculate remaining wait option. */
        remaining_wait_option = (UINT)(wait_option - (nx_bsd_system_clock - start_time));
        if (remaining_wait_option > wait_option)
        {

            /* Wait option expired. */
            status = TX_NO_EVENTS;
        }
        else
        {

            /* Suspend this socket on a RECEIVE event (incoming packet) for the specified wait time.  */
            status =  tx_event_flags_get(&nx_bsd_events, NX_BSD_RECEIVE_EVENT, TX_OR_CLEAR, &requested_events, remaining_wait_option);
        }

        /* Check for any events. */
        if (status == TX_NO_EVENTS)
        {

            /* No packets received. */

            /* Set the socket error depending if this is a non blocking socket. */
            if ((bsd_socket_ptr -> nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING) || 
                (wait_option == NX_WAIT_FOREVER) ||
                (flags & MSG_DONTWAIT))
                set_errno(EWOULDBLOCK);  
            else
                set_errno (EAGAIN);  

            /* Return an error.  */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR);
        }
        else if (status != TX_SUCCESS)
        {
        
            /* Set the socket error if extended socket options enabled. */
            set_errno(EINVAL);  

            /* Return an error.  */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR); 
        }

        /* Re-obtain the protection mutex.  */
        status = tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);               

        /* Check the status.  */
        if (status)
        {

            /* Set the socket error if extended socket options enabled. */
            set_errno(EACCES);  

            /* Return an error.  */
            NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
            return(NX_SOC_ERROR); 
        }

        if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
        {
            /* The socket is no longer in use. */

            /* Set the socket error code. */
            set_errno(EBADF);

            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            /* Return error code.  */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR);
        }
       
    } while (1);

    /* At this point, the socket has received a packet.  */
    

    /* Obtain sender information for UDP socket. */
    if(bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_UDP)
    {    

        /* Get the sender and port from the UDP packet.  */ 
        nx_udp_source_extract(packet_ptr, &bsd_socket_ptr -> nx_bsd_socket_source_ip_address, (UINT *)&bsd_socket_ptr -> nx_bsd_socket_source_port);        
    }

#if defined(NX_BSD_RAW_SUPPORT) || defined(NX_BSD_RAW_PPPOE_SUPPORT)
    else if(bsd_socket_ptr -> nx_bsd_socket_family == AF_PACKET)
    {

        /* Validate the packet length.  */
        if (packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr < 14)
        {

            /* Set the socket error if extended socket options enabled. */
            set_errno(EINVAL);

            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            /* Release the packet.  */
            nx_packet_release(packet_ptr);

            /* Return an error.  */
            NX_BSD_ERROR(status, __LINE__);
            return(NX_SOC_ERROR);
        }

        /* Pick up the sender's MAC address. */
        bsd_socket_ptr -> nx_bsd_socket_sll_addr[0] = packet_ptr -> nx_packet_prepend_ptr[6];
        bsd_socket_ptr -> nx_bsd_socket_sll_addr[1] = packet_ptr -> nx_packet_prepend_ptr[7];
        bsd_socket_ptr -> nx_bsd_socket_sll_addr[2] = packet_ptr -> nx_packet_prepend_ptr[8];
        bsd_socket_ptr -> nx_bsd_socket_sll_addr[3] = packet_ptr -> nx_packet_prepend_ptr[9];
        bsd_socket_ptr -> nx_bsd_socket_sll_addr[4] = packet_ptr -> nx_packet_prepend_ptr[10];
        bsd_socket_ptr -> nx_bsd_socket_sll_addr[5] = packet_ptr -> nx_packet_prepend_ptr[11];

        /* Pick up the sender's protocol */
        bsd_socket_ptr -> nx_bsd_socket_sll_protocol = (USHORT)((packet_ptr -> nx_packet_prepend_ptr[12] << 8) | 
                                                                (packet_ptr -> nx_packet_prepend_ptr[13]));
        if (bsd_socket_ptr -> nx_bsd_socket_sll_protocol == 0x8100)
        {
            
            /* Skip VLAN tag. */
            bsd_socket_ptr -> nx_bsd_socket_sll_protocol = (USHORT)((packet_ptr -> nx_packet_prepend_ptr[16] << 8) | 
                                                                    (packet_ptr -> nx_packet_prepend_ptr[17]));
        }

        /* Find the IF Index */
        bsd_socket_ptr -> nx_bsd_socket_sll_ifindex = (packet_ptr -> nx_packet_ip_interface - nx_bsd_default_ip -> nx_ip_interface) / sizeof(NX_INTERFACE);

    }
#endif /* defined(NX_BSD_RAW_SUPPORT) || defined(NX_BSD_RAW_PPPOE_SUPPORT) */



    /* Pickup the current offset.  */
    offset =  bsd_socket_ptr -> nx_bsd_socket_received_packet_offset;



    /* Copy the packet data into the supplied buffer.  */
    status =  nx_packet_data_extract_offset(packet_ptr, offset, (VOID*)((INT)rcvBuffer + header_size), (ULONG) (bufferLength - header_size), &bytes_received);
    
    /* Check for an error.  */
    if (status)
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL); 
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
        
        /* Release the packet.  */
        nx_packet_release(packet_ptr);
        
        /* Return an error.  */
        NX_BSD_ERROR( status, __LINE__);
        return(NX_SOC_ERROR);
    }
    
    if((flags & MSG_PEEK) == 0)
    {

        /* Calculate the new offset.  */
        offset =  offset + bytes_received;

        /* Determine if all the packet data was consumed.  */
        if(packet_ptr -> nx_packet_length <= offset)
        {
        
            bsd_socket_ptr -> nx_bsd_socket_received_packet =  packet_ptr -> nx_packet_queue_next;

            /* Release the packet.  */
            nx_packet_release(packet_ptr);
            
            /* Clear the offset.  */
            bsd_socket_ptr -> nx_bsd_socket_received_packet_offset =  0;
        }
        else if((bsd_socket_ptr -> nx_bsd_socket_protocol != NX_PROTOCOL_TCP)
               )
        {

            /* For UDP socket, We extracted as much as can fit in the caller's buffer. 
               We will discard the remaining bytes. */
            bsd_socket_ptr -> nx_bsd_socket_received_packet =  packet_ptr -> nx_packet_queue_next;

            bytes_received = packet_ptr -> nx_packet_length;

            /* No need to retain the packet.  */
            nx_packet_release(packet_ptr);

            /* Clear the offset.  */
            bsd_socket_ptr -> nx_bsd_socket_received_packet_offset =  0;
        }
        else
        {
        
            /* For TCP, the remaining data is saved for the next recv call. 
               Just update the offset.  */
            bsd_socket_ptr -> nx_bsd_socket_received_packet_offset =  offset;
        }
        bsd_socket_ptr -> nx_bsd_socket_received_byte_count -= bytes_received;
        bsd_socket_ptr -> nx_bsd_socket_received_packet_count--;
    }

    /* Release the protection mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);

    /* Successful received a packet. Return the number of bytes copied to buffer.  */
    return((INT)bytes_received + (INT)header_size);
}


/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    recvfrom                                            PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */
/*    This function copies up to a specified number of bytes, received on */
/*    the socket into a specified location. To use recvfrom() on a TCP    */
/*    socket requires the socket to be in the connected state.            */
/*                                                                        */
/*    This function is identical to recv() except for returning the sender*/
/*    address and length if non null arguments are supplied.              */  
/*                                                                        */
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    sockID                                Socket(must be connected)     */
/*    buffer                                Pointer to hold data received */
/*    bufferSize                            Maximum number of bytes       */ 
/*    flags                                 Control flags, support        */
/*                                            MSG_PEEK and MSG_DONTWAIT   */
/*    fromAddr                              Address data of sender        */
/*    fromAddrLen                           Length of address structure   */
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    number of bytes received              If no error occurs            */
/*    NX_SOC_ERROR (-1)                     In case of any error          */
/*                                                                        */
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    memset                                Clear memory                  */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nx_packet_data_extract_offset         Extract packet data           */
/*    nx_packet_release                     Free the packet used          */
/*    tx_mutex_get                          Get protection                */
/*    tx_mutex_put                          Release protection            */
/*    tx_event_flags_get                    Wait for data to arrive       */
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
/*  09-30-2020     Yuxin Zhou               Modified comment(s), and      */
/*                                            verified memcpy use cases,  */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
INT  recvfrom(INT sockID, CHAR *rcvBuffer, INT bufferLength, INT flags, struct sockaddr *fromAddr, INT *fromAddrLen)
{

INT                  bytes_received;
NX_BSD_SOCKET       *bsd_socket_ptr;
struct sockaddr_in  peer4_address;

    /* Check for a valid socket ID. */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);
        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Set up a pointer to the socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID - NX_BSD_SOCKFD_START];

    /* Socket error checking is done inside recv() call. */

    /* Call the equivalent recv() function. */
    bytes_received = recv(sockID, rcvBuffer, bufferLength, flags);

    /* Check for error. */
    if (bytes_received < 0)
    {

        /* Return an error status. */
        return NX_SOC_ERROR;
    }
    /* If no bytes are received do not handle as an error. */
    else if (bytes_received == 0)
    {
        return NX_SOC_OK;
    }

    /* At this point we did receive a packet. */
    /* Supply the sender address if valid pointer is supplied. */
    if(fromAddr && (*fromAddrLen != 0))
    {

        /* Handle the IPv4 socket type. */
        if(bsd_socket_ptr -> nx_bsd_socket_family == AF_INET)
        {
            /* Update the Client address with socket family, remote host IPv4 address and port.  */
            peer4_address.sin_family =      AF_INET;
            if(bsd_socket_ptr -> nx_bsd_socket_tcp_socket)
            {
                peer4_address.sin_addr.s_addr = htonl(bsd_socket_ptr -> nx_bsd_socket_peer_ip);
                peer4_address.sin_port = htons(bsd_socket_ptr -> nx_bsd_socket_peer_port);
            }
            else
            {
                peer4_address.sin_addr.s_addr = ntohl(bsd_socket_ptr -> nx_bsd_socket_source_ip_address);

                    peer4_address.sin_port =    ntohs((USHORT)bsd_socket_ptr -> nx_bsd_socket_source_port);
            }
            /* Copy the peer address/port info to the ClientAddress.  Truncate if
               addressLength is smaller than the size of struct sockaddr_in */
            if(*fromAddrLen > (INT)sizeof(struct sockaddr_in))
            {
                *fromAddrLen = sizeof(struct sockaddr_in);
            }
            memcpy(fromAddr, &peer4_address, (UINT)(*fromAddrLen)); /* Use case of memcpy is verified. */
        }
        else

#if defined(NX_BSD_RAW_PPPOE_SUPPORT) || defined(NX_BSD_RAW_SUPPORT)
        if(bsd_socket_ptr -> nx_bsd_socket_family == AF_PACKET)
        {
            if(*fromAddrLen >= (INT)sizeof(struct sockaddr_ll))
            {
                struct sockaddr_ll *sockaddr = (struct sockaddr_ll*)fromAddr;
                INT i;
                sockaddr -> sll_family = AF_PACKET;
                sockaddr -> sll_protocol = bsd_socket_ptr -> nx_bsd_socket_sll_protocol;
                sockaddr -> sll_ifindex = bsd_socket_ptr -> nx_bsd_socket_sll_ifindex;
                sockaddr -> sll_hatype = 0;
                sockaddr -> sll_pkttype = 0;
                sockaddr -> sll_halen = 6;
                for(i = 0; i < 6; i++)
                    sockaddr -> sll_addr[i] = bsd_socket_ptr -> nx_bsd_socket_sll_addr[i];
                *fromAddrLen = sizeof(struct sockaddr_ll);
            }

        }
        else
#endif
        {
            
            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);
            
            /* Set the socket error if extended socket options enabled. */
            set_errno(EINVAL);  
            
            /* Error, IPv6 support is not enabled.  */
            NX_BSD_ERROR(ERROR, __LINE__);
            return(ERROR);
        }
    }

    /* Successfully received a packet. Return bytes received. */
    return (INT)(bytes_received);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    soc_close                                           PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function terminates communications on the supplied BSD socket. */
/*    The socket is disallowed for further sends and receives. Socket     */
/*    resources such as socket memory are returned to the system.         */
/*                                                                        */
/*    If a socket is enabled with the linger option, that will be used in */
/*    place of the default NX_BSD TIMEOUT for blocking sockets.  Sockets  */
/*    enabled for non blocking have their timeout set for zero. Note that */
/*    a zero wait option results in an immediate shutdown (e.g. send RST) */
/*    unless the NX_DISABLE_RESET_DISCONNECT is not enabled.              */
/*                                                                        */
/*    For BSD applications enabled for disconnect complete notification   */
/*    for TCP sockets, the socket will remain open until NetX notifies us */
/*    that the disconnect is complete.  This allows the host BSD          */
/*    application to perform asynchronous disconnects without having to   */
/*    wait for the disconnect to complete.                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socketID                                                            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SOC_OK (0)                         On success                    */
/*    NX_SOC_ERROR (-1)                     On failure                    */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                                Clear memory                  */
/*    nx_tcp_socket_disconnect              Disconnect a TCP Socket       */
/*    nx_tcp_client_socket_unbind           Unbind the socket             */
/*    nx_tcp_server_socket_unaccept         Unaccept the socket           */
/*    nx_tcp_server_socket_unlisten         Unlisten on a port            */
/*    nx_tcp_socket_delete                  Deletes a TCP Socket          */
/*    nx_udp_socket_unbind                  Unbind a UDP Socket           */
/*    nx_udp_socket_delete                  Deletes a UDP Socket          */
/*    tx_block_release                      Release block for socket      */
/*    tx_mutex_get                          Get protection                */
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
INT  soc_close(INT sockID)
{

NX_BSD_SOCKET       *bsd_socket_ptr;
NX_TCP_SOCKET       *tcp_socket_ptr;
NX_UDP_SOCKET       *udp_socket_ptr;
NX_PACKET           *packet_ptr;
NX_PACKET           *next_packet_ptr;
ULONG                timeout;
INT                  i;
UINT                 counter;
INT                  delete_socket;

    /* Check for a valid socket ID.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error. */
        set_errno(EBADF);

        /* Error, invalid socket ID.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;

    /* Set up a pointer to the BSD socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    /* Get the protection mutex.  */
    tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Is the socket already in use?  */
    if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
    {

        /* No; If the NetX socket associated with this BSD socket been deleted, this is ok. */
        if (!bsd_socket_ptr -> nx_bsd_socket_tcp_socket && !bsd_socket_ptr -> nx_bsd_socket_udp_socket)
        {

            /* Yes, no further action possible. Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            return NX_SOC_OK;
        }

        /* Otherwise, it is an error if socket not in use anymore.  */

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);  

        /* Return error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }        

    /* Set NetX socket pointers.  */
    tcp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_tcp_socket;
    udp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_udp_socket;

    /* There is. Flush the queue of all packets. */
    packet_ptr = bsd_socket_ptr -> nx_bsd_socket_received_packet;
    /* Setup packet pointer to the beginning of the queue.  */
    while(packet_ptr)
    {
        next_packet_ptr = packet_ptr -> nx_packet_queue_next;

        /* Mark it as allocated so it will be released.  */
        packet_ptr -> nx_packet_queue_next =  (NX_PACKET *) NX_PACKET_ALLOCATED;            

        nx_packet_release(packet_ptr);

        /* Move to the next packet */
        packet_ptr = next_packet_ptr;
    }

    bsd_socket_ptr -> nx_bsd_socket_received_packet = NX_NULL;
    bsd_socket_ptr -> nx_bsd_socket_received_packet_tail = NX_NULL;
    bsd_socket_ptr -> nx_bsd_socket_received_byte_count = 0;
    bsd_socket_ptr -> nx_bsd_socket_received_packet_count = 0;
    bsd_socket_ptr -> nx_bsd_socket_received_packet_count_max = 0;

    /* Now delete the underlying TCP or UDP socket. */

    /* Is this a TCP socket? */
    if (tcp_socket_ptr)
    {

        /* If the socket has not been closed, disconnect it. This would be the case
           if NetX already closed the socket e.g. a RST packet received before the 
           host application called this function. */
        if (tcp_socket_ptr -> nx_tcp_socket_state != NX_TCP_CLOSED)
        {

            /* Disconnect the socket. */

            /* If the disconnect takes more than the timeout option, NetX marks the socket as "closed" 
               or puts it back to "listen" state. The default value is 1 to emulate an immediate
               socket closure without sending a RST packet.  */
            timeout = NX_BSD_TCP_SOCKET_DISCONNECT_TIMEOUT;

            /* Release the mutex while disconnecting. */
            tx_mutex_put(nx_bsd_protection_ptr);

            nx_tcp_socket_disconnect(tcp_socket_ptr, timeout);

            tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

            /* Verify that the socket is still valid. */
            if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
            {
                /* The socket is no longer in use. */
                
                /* Set the socket error code. */
                set_errno(EBADF);
                
                /* Release the protection mutex.  */
                tx_mutex_put(nx_bsd_protection_ptr);
                
                /* Return error code.  */
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return(NX_SOC_ERROR);
            }
        }
        /* Make sure the socket is unbound, not accepting connections and not bound to a listening port. */
        if(tcp_socket_ptr -> nx_tcp_socket_port)
        {

            if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CLIENT)
            {
                nx_tcp_client_socket_unbind(tcp_socket_ptr);
            }
            else
            {
                nx_tcp_server_socket_unaccept(tcp_socket_ptr);
            }

        }

        /* Now we can delete the NetX TCP socket.  */
        nx_tcp_socket_delete(tcp_socket_ptr);

        /* Clear the TCP socket structure.  */
        memset((VOID *) tcp_socket_ptr, 0, sizeof(NX_TCP_SOCKET));
        
        /* Release the NetX TCP socket.  */
        tx_block_release((VOID *) tcp_socket_ptr);
        
        /* If this is the master server socket, we need to unaccept the 
           associated secondary socket. */
        if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_MASTER_SOCKET)
        {

            INT sec_soc_id = (bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id;
            
            if(sec_soc_id < NX_BSD_MAX_SOCKETS)
            {

                /* Find whether or not this is the only master socket that is connected to this 
                   secondary socket. */
                for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
                {

                    if(i == sockID)
                        continue;

                    if((nx_bsd_socket_array[i].nx_bsd_socket_protocol == NX_PROTOCOL_TCP) &&
                       (nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_MASTER_SOCKET) &&
                       (nx_bsd_socket_array[i].nx_bsd_socket_union_id.nx_bsd_socket_secondary_socket_id == sec_soc_id))
                    {
                        break;
                    }
                }

                if(i == NX_BSD_MAX_SOCKETS)
                {

                    /* Unaccept and unlisten on the socket/port */
                    /* nx_tcp_server_socket_unaccept(tcp_socket_ptr); */
                    /* nx_tcp_server_socket_unlisten(nx_bsd_default_ip, tcp_socket_ptr -> nx_tcp_socket_port); */

                    /* Release the secondary socket if there are no more master sockets associated
                       with this secondary socket. */
                      
                    tcp_socket_ptr = nx_bsd_socket_array[sec_soc_id].nx_bsd_socket_tcp_socket;

                    /* If the secondary socket has not been closed, disconnect it. This would be the case
                       if NetX already closed the master socket. */
                    if (tcp_socket_ptr -> nx_tcp_socket_state != NX_TCP_CLOSED)
                    {

                        /* Disconnect the socket. */

                        /* If the disconnect takes more than the timeout option, NetX marks the socket as "closed" 
                           or puts it back to "listen" state. The default value is 1 to emulate an immediate
                           socket closure without sending a RST packet.  */
                        timeout = NX_BSD_TCP_SOCKET_DISCONNECT_TIMEOUT;

                        /* Release the mutex while disconnecting. */
                        tx_mutex_put(nx_bsd_protection_ptr);

                        nx_tcp_socket_disconnect(tcp_socket_ptr, timeout);

                        tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

                        /* Verify that the socket is still valid. */
                        if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
                        {
                            /* The socket is no longer in use. */

                            /* Set the socket error code. */
                            set_errno(EBADF);

                            /* Release the protection mutex.  */
                            tx_mutex_put(nx_bsd_protection_ptr);

                            /* Return error code.  */
                            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                            return(NX_SOC_ERROR);
                        }
                    }

                    /* Unaccept on the secondary socket. */
                    nx_tcp_server_socket_unaccept(tcp_socket_ptr);
                    nx_tcp_server_socket_unlisten(nx_bsd_default_ip, tcp_socket_ptr -> nx_tcp_socket_port);
                    nx_tcp_socket_delete(tcp_socket_ptr);
                    
                    memset((VOID*)tcp_socket_ptr, 0, sizeof(NX_TCP_SOCKET));
                    tx_block_release((VOID*)tcp_socket_ptr);
                    memset((VOID*)&(nx_bsd_socket_array[sec_soc_id]), 0, sizeof(NX_BSD_SOCKET));
                }
            }
        }

        /* Finally Clear the BSD socket structure.  */
        memset((VOID *) bsd_socket_ptr, 0, sizeof(NX_BSD_SOCKET));
        
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Return */
        return(NX_SOC_OK);
        
    }
    else if (udp_socket_ptr)
    {   
    
        /* A UDP socket needs to be closed.  */

        /* Check whether this is the last BSD socket attached to the NX_UDP_SOCKET */
        counter = (UINT)udp_socket_ptr -> nx_udp_socket_reserved_ptr;

        delete_socket = NX_TRUE;
        /* Decrease the counter value. */
        if(counter & 0xFFFF0000)
        {

            counter = ((counter & 0xFFFF0000) - 0x00010000 + (counter & 0x0000FFFF)) & 0xFFFFFFFF;

            udp_socket_ptr -> nx_udp_socket_reserved_ptr = (VOID*)counter;

            if(counter & 0xFFFF0000)
            {

                /* Do not delete this socket. */
                delete_socket = NX_FALSE;

                /* If the underlying NX_UDP_SOCKET points to this UDP socket, we need to 
                   reassign a BSD socket to the NX UDP socket. */
                for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
                {

                    if((nx_bsd_socket_array[i].nx_bsd_socket_udp_socket == udp_socket_ptr) &&
                       (i != sockID))
                    {

                        counter = (counter & 0xFFFF0000) + (UINT)i;
                        udp_socket_ptr -> nx_udp_socket_reserved_ptr = (VOID*)counter;
                        break;
                    }
                }

                if(i == NX_BSD_MAX_SOCKETS)
                {
                    delete_socket = NX_TRUE;
                }
            }
        }

        if(delete_socket == NX_TRUE)
        {

            if(udp_socket_ptr -> nx_udp_socket_bound_next)
            {
                nx_udp_socket_unbind(udp_socket_ptr);
            }            
            
            /* Socket successfully unbound. Now delete the UDP socket.  */
            nx_udp_socket_delete(udp_socket_ptr);
            
            /* Clear the UDP socket block.  */
            memset((VOID *) udp_socket_ptr, 0, sizeof(NX_UDP_SOCKET));
            
            /* Release the NetX UDP socket memory.  */
            tx_block_release((VOID *) udp_socket_ptr);
        }
        else
        {
            /* Remove this bsd udp socket from the list. */
            (bsd_socket_ptr -> nx_bsd_socket_next) -> nx_bsd_socket_previous = bsd_socket_ptr -> nx_bsd_socket_previous;
            (bsd_socket_ptr -> nx_bsd_socket_previous) -> nx_bsd_socket_next = bsd_socket_ptr -> nx_bsd_socket_next;
        }

        /* Clear the BSD socket block.  */
        memset((VOID *) bsd_socket_ptr, 0, sizeof(NX_BSD_SOCKET));

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);                

        return(NX_SOC_OK);
    }

#if defined(NX_BSD_RAW_PPPOE_SUPPORT) || defined(NX_BSD_RAW_SUPPORT)
    else if(bsd_socket_ptr -> nx_bsd_socket_family == AF_PACKET)
    {
        /* There is no native NetX Duo raw socket to delete or
           port to unbind. So just release the BSD socket memory.  */

        /* Clear the BSD socket block.  */
        memset((VOID *) bsd_socket_ptr, 0, sizeof(NX_BSD_SOCKET));

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        return(NX_SOC_OK);
    }

#endif /* defined(NX_BSD_RAW_PPPOE_SUPPORT) || defined(NX_BSD_RAW_SUPPORT) */




    /* Unknown socket type or invalid socket. */
    
    /* Release the protection mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);
    
    /* Set the socket error if extended socket options enabled. */
    set_errno(EINVAL);  
    
    /* Return error.  */
    NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
    return(NX_SOC_ERROR);



}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    fcntl                                               PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function performs the requested operation on the file (e.g.    */
/*    socket) descriptor set.  This implementation supports only the set  */
/*    or get flag, and only sets (or clears) the non blocking option.     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    sockID                                socket descriptor             */
/*    flag_type                             File description request      */
/*    f_options                             Option(s) to set on the       */
/*                                              specified file (socket)   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SOC_ERROR                          Errors with request           */
/*    (file descriptor flags)               File descriptor flags         */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection                */
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
INT fcntl(INT sockID, UINT flag_type, UINT f_options)
{

NX_BSD_SOCKET   *bsd_socket_ptr;

    /* Check for invalid socket ID. */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);

        /* Return error status. */
        return NX_SOC_ERROR;
    }

    /* Normalize the socket ID to our array. */
    sockID =  sockID - NX_BSD_SOCKFD_START; 

    /* Build pointer to BSD socket structure.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    if(flag_type == F_SETFL)
    {
        /* Set the FD flag. */
        bsd_socket_ptr -> nx_bsd_file_descriptor_flags = (INT)f_options;


        /* Are there flags to clear? */
        if ((f_options & O_NONBLOCK) == 0)
        {
            /* Disable the socket for non blocking. */
            bsd_socket_ptr -> nx_bsd_socket_option_flags &= (ULONG)(~NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING);
        }
        else
        {
            /* Enable the socket for non blocking. */
            bsd_socket_ptr -> nx_bsd_socket_option_flags |= NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING;
        }

        /* All done. Return 0 */
        return(0);
    }
    else if(flag_type == F_GETFL)
    {
        return(bsd_socket_ptr -> nx_bsd_file_descriptor_flags);
    }
    /* Flag_type is not the one we support */

    /* Set the socket error if extended socket options enabled. */
    set_errno(EINVAL);  
    
    NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
    
    /* Return error status. */
    return NX_SOC_ERROR;



}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    ioctl                                               PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function carries out a socket IO service specified by the      */
/*    command.                                                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    sockID                                Socket (must be connected).   */
/*    command                               IO command for ioctl function */
/*    result                                data returned (value)         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    Number of bytes received              If success                    */
/*    NX_SOC_ERROR (-1)                     Error during socket opration  */
/*    NX_SOC_OK (0)                         Successful completion         */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_tcp_socket_bytes_available         Retreive number of bytes on   */
/*                                               the specified TCP socket */
/*    nx_udp_socket_bytes_available         Retreive number of bytes on   */
/*                                               the specified UDP socket */
/*    tx_mutex_get                          Get protection                */
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
INT  ioctl(INT sockID,  INT command, INT *result)
{

NX_BSD_SOCKET       *bsd_socket_ptr;
NX_TCP_SOCKET       *tcp_socket_ptr;
NX_UDP_SOCKET       *udp_socket_ptr;
UINT                status;


    /* Check that the supplied socket ID is valid.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Error, invalid socket ID.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;

    /* Get the protection mutex.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status)
    {

        /* Error getting the protection mutex.  */
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Set a pointer to the BSD socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    /* Pick up the associated NetX socket pointers.  */
    tcp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_tcp_socket;
    udp_socket_ptr =  bsd_socket_ptr -> nx_bsd_socket_udp_socket;

    /* Handle the command. */
    switch (command)
    {

        case FIONREAD:
        {

            /* Check NULL pointer. */
            if(result == NX_NULL)
            {
                tx_mutex_put(nx_bsd_protection_ptr); 

                set_errno(EFAULT);

                /* Error, invalid address. */ 
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);

                return(NX_SOC_ERROR);
            }

            /* Determine which socket pointer to use.  */        
            if (tcp_socket_ptr)
            {

                /* Extract the number of bytes on the TCP receive queue. */
                status = nx_tcp_socket_bytes_available(tcp_socket_ptr, (ULONG *)result);

                if (status != NX_SUCCESS)
                {

                    tx_mutex_put(nx_bsd_protection_ptr); 

                    /* Error in the native NetX call.  */
                    NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
                    return(NX_SOC_ERROR); 
                }
            }
            else if (udp_socket_ptr)
            {

                /* Extract the number of bytes on the UDP receive queue. */
                *result = (INT)(bsd_socket_ptr ->  nx_bsd_socket_received_byte_count);
            }

            break;
        }

        case FIONBIO:
        {    

            /* Check NULL pointer. */
            if(result == NX_NULL)
            {
                tx_mutex_put(nx_bsd_protection_ptr); 

                set_errno(EFAULT);

                /* Error, invalid address. */ 
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);

                return(NX_SOC_ERROR);
            }

            if(*result == NX_FALSE)
            {

                /* Disable the socket for non blocking. */        
                bsd_socket_ptr -> nx_bsd_socket_option_flags &= (ULONG)(~NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING);

                /* Update the file descriptor with the non blocking bit. */
                bsd_socket_ptr -> nx_bsd_file_descriptor_flags  &= ~O_NONBLOCK;
            }
            else
            {

                /* Enable the socket for non blocking. */        
                bsd_socket_ptr -> nx_bsd_socket_option_flags |= NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING;

                /* Update the file descriptor with the non blocking bit. */
                bsd_socket_ptr -> nx_bsd_file_descriptor_flags  |= O_NONBLOCK;
            }

            break;
        }

        default:

            /* Unhandled command; ignore  */
            break;
    }

    tx_mutex_put(nx_bsd_protection_ptr); 

    return NX_SOC_OK; 
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    inet_ntoa                                           PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function converts an IP address to a string and returns a      */
/*    pointer to the string.  The caller is recommended to copy the       */
/*    contents of the buffer to local memory since this function and      */
/*    internal buffer can be reused.                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    address_to_convert                    Struct holding IP address.    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    char *                                Pointer to converted string   */
/*    0x0                                   Error during conversion       */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get mutex protection          */
/*    bsd_number_convert                    Convert integer to ascii      */
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
CHAR *inet_ntoa(struct in_addr address_to_convert)
{
UINT status;

    /* Because we are using global buffer space to write out the string, get the protection mutex.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    if (status != NX_SUCCESS)
    {
        return NX_NULL;
    }

    inet_ntoa_internal(&address_to_convert, nx_bsd_url_buffer, NX_BSD_URL_BUFSIZE);

    tx_mutex_put(nx_bsd_protection_ptr);

    /* Return the start of the string buffer. */
    return nx_bsd_url_buffer;
                    
}

/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    bsd_number_convert                                  PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*    This function converts an integer to a string.                      */
/*                                                                        */
/*  INPUT                                                                 */  
/*                                                                        */  
/*    number                                Number to convert             */  
/*    string                                Pointer to string buffer      */
/*    buffer_len                            Size of the string buffer     */
/*    base                                  the base of the number,       */
/*                                          2,8,10,16                     */
/*                                                                        */  
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    size                                  Size of string buffer         */ 
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
UINT  bsd_number_convert(UINT number, CHAR *string, ULONG buffer_len, UINT base)
{

UINT    j;
UINT    digit;
UINT    size;


    /* Initialize counters.  */
    size =  0;

    /* Loop to convert the number to ASCII.  */
    while (size < buffer_len)
    {

        /* Shift the current digits over one.  */
        for (j = size; j != 0; j--)
        {

            /* Move each digit over one place.  */
            string[j] =  string[j-1];
        }

        /* Compute the next decimal digit.  */
        digit =  number % base;

        /* Update the input number.  */
        number =  number / base;

        /* Store the new digit in ASCII form.  */
        if(digit < 10)
            string[0] =  (CHAR) (digit + 0x30);
        else
            string[0] =  (CHAR) (digit + 0x57);

        /* Increment the size.  */
        size++;

        /* Determine if the number is now zero.  */
        if (number == 0)
            break;
    }

    /* Make the string NULL terminated.  */
    string[size] =  (CHAR) NX_NULL;

    /* Determine if there is an overflow error.  */
    if (number)
    {

        /* Error, return bad values to user.  */
        size =  0;
        string[0] = '0';
    }

    /* Return size to caller.  */
    return(size);
}

/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    inet_aton                                           PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*    This function converts hexadecimal characters into an ASCII IP      */
/*    address representation.                                             */
/*                                                                        */
/*  INPUT                                                                 */  
/*                                                                        */  
/*    address_buffer_ptr                    String holding the IP address */ 
/*    addr                                  Struct to store the IP address*/
/*                                                                        */
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    NX_SUCCESS                            Successful conversion         */ 
/*    NX_SOC_ERROR                          Error during conversion       */
/*                                                                        */  
/*  CALLS                                                                 */  
/*                                                                        */  
/*    nx_bsd_isdigit                        Indicate char is a number     */
/*    isspace                               Indicate char is a space      */
/*    islower                               Indicate char is lowercase    */
/*    htonl                                 Convert to network byte order */
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
INT inet_aton(const CHAR *address_buffer_ptr, struct in_addr *addr)
{
ULONG value;
INT   base = 10, ip_address_index;
UCHAR tempchar;
const UCHAR *buffer_ptr;
UINT  ip_address_number[4];  /* Four discreet numbers in IP address representation. */
UINT *ip_number_ptr;         /* IP address as equivalent ULONG value. */
UINT  dot_flag;   

    /* Set local variables. */
    buffer_ptr = (const UCHAR *) address_buffer_ptr;
    ip_number_ptr = ip_address_number;

    tempchar = *buffer_ptr;

    /* Check for an invalid first character. */
    if (nx_bsd_isdigit(tempchar)== NX_FALSE)
    {
        return (0);
    }

    dot_flag = 1;

    /* Parse the rest of the characters from the input number. */
    do
    {

        /* Initialize the (next) extracted IP address number to zero. */
        value = 0; 

        if(dot_flag== 1)
        {
            /* Initialize the numeric base to decimal unless we determine hex or octal. */
            base = 10;

            /* Determine which number base the input number buffer is. */
            if (*buffer_ptr == '0') 
            {
                /* Get the next character. */
                buffer_ptr++;

                /* A leading 0 followed by an 'x' indicates this is hexidecimal. */
                if ((*buffer_ptr== 'x') || (*buffer_ptr == 'X'))
                {
                    base = 16;

                    /* Move ahead one character past the leading '0x' */
                    buffer_ptr++;
                }
                else
                {
                    /* This is octal. */
                    base = 8;
                    buffer_ptr--;
                }
            }
        }

        tempchar = *buffer_ptr;

        /* Parse characters making up the next word. */
        while (*buffer_ptr != '\0') 
        {
            /* Check if the next character is a decimal or octal digit. */
            if (nx_bsd_isdigit(tempchar)) 
            {

                dot_flag = 0;

                /* Convert the tempchar character to a number.  Multiply the existing 
                   number by the base (8 or 10) and this digit to the sum. */
                value = (value * (ULONG)base) + (ULONG)(tempchar - '0');

                /* Advance the IP address pointer to the next character. */
                buffer_ptr++;

                /* Get the next character. */
                tempchar = *buffer_ptr;
            }
            /* Else check if we are expecting a hexidecimal number. */
            else if (nx_bsd_isxdigit(tempchar))
            {
                /* We are; Verify the base is 16. */
                if(base == 16)
                {

                    /* It is.  handle upper or lower case hex digit. */
                    CHAR c = (CHAR)(nx_bsd_islower(tempchar) ? 'a' : 'A');

                    dot_flag = 0;

                    /* Convert the hex character to a hex digit, multiply the existing word by shifting the bits,
                       and add this hex digit to the sum. */
                    value = (value << 4) + (ULONG)(tempchar + 10 - c);

                    buffer_ptr++;

                    /* Get the next character. */
                    tempchar = *buffer_ptr;
                }
                else
                {
                    /* Not a valid hex character. */
                    return (0);
                }                    
            }
            else
            {
                /* We have reached a number separator or possibly end of the string.  */
                break;
            }
        }

        /* At the end of the current word. Is this a separator character? */
        if (*buffer_ptr == '.') 
        {

            dot_flag = 1;

            /* Yes, check for an invalid number (cannot exceed 255 or 0xFF. */
            if (value > 0xff)
            {
                return (0);
            }

            /* Check that the pointer to the last extracted number does not exceed the array holding the IP address numbers. */
            if (ip_number_ptr >= (ip_address_number + 3))
            {
                return (0);
            }

            /* Copy the computed value into the IP address number buffer. */
            *ip_number_ptr = value;

            /* Move the pointer to where we will store the next number extracted. */
            ip_number_ptr++;

            /* Move to the next character in the IP address string. */
            buffer_ptr++;
        } 
        /* Check for non digit or seperator character indicating (maybe) end of the buffer. */
        else
            break;

    } while (1);

    /* If this is not a null terminating character, check for invalid trailing characters. */
    if (*buffer_ptr)
    {

        if((*buffer_ptr != '\0') && (!nx_bsd_isspace(*buffer_ptr)))
        {

            return (0);
        }
    }

    /* IP addresses are grouped as A, B, C, or D types.  Determine which 
       type address we have by comparing the IP address value against...*/

    /* Determine this by substracting the pointer to beginning of the whole 
       IP address number ip_number_ptr[4] against the pointer to the last extracted word, ip_address_number. */
    ip_address_index = ip_number_ptr - ip_address_number + 1;

    /* Check for an invalid array index (assume 'the array' is indexed 1-4). */
    if ((ip_address_index == 0) || (ip_address_index > 4))
    {
        return (0);
    }

    /* Sum each of the individual IP address numbers depending how many there were extracted. */

    /* Most common input... */
    if (ip_address_index == 4)
    {
        INT i;

        /* Three separators parsed, so the format is a.b.c.d where c is 8 bits */

        /* Check for a computed sum greater than can be contained in 8 bits. */
       if (value > 0xff)
           return (0);

       /* 'Add' the last extracted number by prepending the three other bytes onto the total value. */
       for (i = 0; i<=2; i++)
       {
           value |= ip_address_number[i] << (24 - (i*8));
       }
    }
    /* Most common input... */
    else if (ip_address_index == 1) 
    {

        /* We are done, this address contained one 32 bit word (no separators).  */
    }
    /* Less common input... */
    else if (ip_address_index ==  2)
    {
        /* One separator, so the format is a.b where b is 24 bits */

        /* Check for a computed sum greater than can be contained in 24 bits. */
        if (value > 0xffffff)
            return (0);

        /* 'Add' the last extracted number by prepending the most significant byte onto the total value. */
        value |= (ip_address_number[0] << 24);
     }
     else if (ip_address_index ==  3)
     {
        /* Two separators parsed, so the format is a.b.c where c is 16 bits */
         INT i;

         /* Check for a computed sum greater than can be contained in 16 bits. */
        if (value > 0xffff)
            return (0);

        /* 'Add' the last extracted number by prepending the two most significant bytes onto the total value. */
        for (i = 0; i<=1; i++)
        {
            value |= ip_address_number[i] << (24 - (i*8));
        }
     }
    
    /* Check if a return pointer for the address data is supplied. */
    if (addr)
    {

        /* Convert the IP address data to network byte order and return the data. */
        addr->s_addr = htonl(value);
    }

    return (1);
}


/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    inet_addr                                           PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*    This function converts an IP address string to a number. If it      */
/*    detects an error in the conversion it returns a zero address.       */
/*                                                                        */
/*  INPUT                                                                 */  
/*                                                                        */  
/*    buffer                                IP address text buffer        */ 
/*    address                               Converted address number      */
/*                                                                        */
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    NX_SUCCESS                            Successful conversion         */ 
/*    NX_SOC_ERROR                          Error during conversion       */
/*                                                                        */  
/*  CALLS                                                                 */  
/*                                                                        */  
/*    inet_aton                             Indicate char is a space      */
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
in_addr_t inet_addr(const CHAR *buffer) 
{

struct  in_addr ip_address;
UINT    status;

    status = (UINT)inet_aton(buffer, &ip_address);

    if (status == 0)
    {
        return (0xFFFFFFFF);
    }

    return(ip_address.s_addr);
}


/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    getsockopt                                          PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*    This function returns the status of the specified socket option in  */
/*    the current BSD socket session.                                     */
/*                                                                        */
/*  INPUT                                                                 */  
/*                                                                        */  
/*    sockID                                socket descriptor             */
/*    option_level                          Category of option (SOCKET)   */
/*    option_name                           Socket option ID              */
/*    option_value                          Pointer to option value       */
/*    option_value                          Pointer to size of value      */
/*                                                                        */
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    tx_mutex_get                          Get protection                */
/*    tx_mutex_put                          Release protection            */ 
/*                                                                        */  
/*  CALLS                                                                 */  
/*                                                                        */  
/*    NX_SOC_OK                             Request processed successfully*/
/*    NX_SOC_ERROR                          Errors with request           */
/*    (option data)                         Pointer to requested data     */
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
INT  getsockopt(INT sockID, INT option_level, INT option_name, VOID *option_value, INT *option_length)
{

TX_INTERRUPT_SAVE_AREA

INT             status;
NX_BSD_SOCKET   *bsd_socket_ptr;
struct          sock_errno      *so_errno;
struct          sock_keepalive  *so_keepalive;
struct          sock_reuseaddr  *so_reuseaddr;
struct          timeval         *so_rcvtimeval;
struct          sock_winsize    *soc_window_size;
ULONG           ticks;


    /* Check for valid socket ID/descriptor. */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Check for invalid input. */
    if((option_value == NX_NULL) || (option_length == NX_NULL))
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return NX_SOC_ERROR;
    }

    if (option_level == IPPROTO_IP)
    {

        if((option_name <= SO_MAX) ||  (option_name > IP_OPTION_MAX))
        {

            /* Error, one or more invalid arguments.  */

            /* Set the socket error if extended socket options enabled. */
            set_errno(ENOPROTOOPT);              
            
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return NX_SOC_ERROR;
        }
    }
    else if(option_level == SOL_SOCKET)
    {

        if((option_name > SO_MAX) || (option_name < SO_MIN))
        {

            /* Error, one or more invalid arguments.  */
            
            /* Set the socket error if extended socket options enabled. */
            set_errno(ENOPROTOOPT);  
            
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return NX_SOC_ERROR;
        }
    }
    else
    {

        /* Error, one or more invalid arguments.  */

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return NX_SOC_ERROR;
    }

    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;

    /* Get the protection mutex.  */
    status =  (INT)tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);  

    /* Check the status.  */
    if (status)
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);  

        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Setup pointer to socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    status = NX_SOC_OK;
    switch (option_name)
    {

        case SO_ERROR:
        {

           /* If a valid option pointer was supplied, verify it points to a valid data size. */
           if (*option_length < (INT)sizeof(so_errno -> error))
           {

               tx_mutex_put(nx_bsd_protection_ptr);

               /* Set the socket error if extended socket options enabled. */
               set_errno(EINVAL);  

               NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
               return(NX_SOC_ERROR); 
           }

           so_errno = (struct sock_errno *)option_value;

           TX_DISABLE
           if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR) 
           {
               so_errno -> error = bsd_socket_ptr -> nx_bsd_socket_error_code;

               /* Now clear the error code. */
               bsd_socket_ptr -> nx_bsd_socket_error_code = 0;

               /* Clear the error flag.  The application is expected to close the socket at this point.*/  
               bsd_socket_ptr -> nx_bsd_socket_status_flags = bsd_socket_ptr -> nx_bsd_socket_status_flags & (ULONG)(~NX_BSD_SOCKET_ERROR); 
           }
           else
               so_errno -> error = 0;
           TX_RESTORE

           /* Set the actual size of the data returned. */ 
           *option_length = sizeof(struct sock_errno);

        }

        break;

        case SO_KEEPALIVE:

            /* Determine if NetX supports keepalive. */
            
            /* Check to make sure the size arguement is sufficient if supplied. */
            if (*option_length < (INT)sizeof(so_keepalive -> keepalive_enabled))
            {

                tx_mutex_put(nx_bsd_protection_ptr);

                /* Set the socket error if extended socket options enabled. */
                set_errno(EINVAL);  

                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return(NX_SOC_ERROR); 
            }
            
            so_keepalive = (struct sock_keepalive *)option_value;
#ifndef NX_ENABLE_TCP_KEEPALIVE
            so_keepalive -> keepalive_enabled = NX_FALSE;
#else
            so_keepalive -> keepalive_enabled = (INT)(bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_keepalive_enabled);
#endif /* NX_ENABLE_TCP_KEEPALIVE */
            *option_length = sizeof(struct sock_keepalive);

        break;

        case SO_RCVTIMEO:

            /* Check if the receive time out is set. */
            if (bsd_socket_ptr -> nx_bsd_option_receive_timeout == 0)
            {
                tx_mutex_put(nx_bsd_protection_ptr);

                /* Set the socket error if extended socket options enabled. */
                set_errno(EINVAL);  

                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return(NX_SOC_ERROR); 

            }

            so_rcvtimeval = (struct timeval *)option_value;

            ticks = bsd_socket_ptr -> nx_bsd_option_receive_timeout;


            so_rcvtimeval -> tv_usec = (suseconds_t)(ticks * NX_MICROSECOND_PER_CPU_TICK) % 1000000;
            so_rcvtimeval -> tv_sec = (time_t)((ticks * NX_MICROSECOND_PER_CPU_TICK) / 1000000);
            *option_length = sizeof(so_rcvtimeval);

        break;

        case SO_RCVBUF:

            soc_window_size = (struct sock_winsize *)option_value;
            soc_window_size -> winsize = (INT)(bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_rx_window_default);
            *option_length = sizeof(soc_window_size);

        break;

        case SO_REUSEADDR:

            /* Check to make sure the size arguement is sufficient if supplied. */
            if (*option_length < (INT)sizeof(so_reuseaddr -> reuseaddr_enabled))
            {

                tx_mutex_put(nx_bsd_protection_ptr);

                /* Set the socket error if extended socket options enabled. */
                set_errno(EINVAL);  

                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return(NX_SOC_ERROR); 
            }
            
            so_reuseaddr= (struct sock_reuseaddr *)option_value;
            so_reuseaddr -> reuseaddr_enabled = bsd_socket_ptr -> nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_REUSEADDR;
            *option_length = sizeof(struct sock_reuseaddr);

        break;

        case IP_MULTICAST_TTL:

            /* Validate the option length. */
            if(*option_length != sizeof(UCHAR))
            {

                tx_mutex_put(nx_bsd_protection_ptr);

                /* Set the socket error if extended socket options enabled. */
                set_errno(EINVAL);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }

            /* Verify that the socket is still valid. */
            if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
            {

                tx_mutex_put(nx_bsd_protection_ptr);

                /* Set the socket error if extended socket options enabled. */
                set_errno(EBADF);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }

            /* Make sure socket is UDP type. */
            if(bsd_socket_ptr -> nx_bsd_socket_udp_socket == NX_NULL)
            {

                tx_mutex_put(nx_bsd_protection_ptr);
               
                /* Set the socket error if extended socket options enabled. */
                set_errno(ENOPROTOOPT);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }

            /* Set the TTL value. */
            *(UCHAR*)option_value = (UCHAR)(bsd_socket_ptr -> nx_bsd_socket_udp_socket -> nx_udp_socket_time_to_live);
            break;

        default:   

            tx_mutex_put(nx_bsd_protection_ptr);

            /* Set the socket error if extended socket options enabled. */
            set_errno(ENOPROTOOPT);  

            /* Unsupported or unknown option. */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR); 
    }

    /* Release the protection mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);

    return status;
}

/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    setsockopt                                          PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*    This function enables the specified socket option in the current BSD*/
/*    socket session to the specified setting.                            */
/*                                                                        */
/*  INPUT                                                                 */  
/*                                                                        */  
/*    sockID                                socket descriptor             */
/*    option_level                          Category of option (SOCKET)   */
/*    option_name                           Socket option ID              */
/*    option_value                          Pointer to option value       */
/*    option_length                         Size of option value data     */
/*                                                                        */
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    NX_SOC_OK                             Request processed successfully*/
/*    NX_SOC_ERROR                          Errors with request           */
/*                                                                        */  
/*  CALLS                                                                 */  
/*                                                                        */
/*    tx_mutex_get                          Get protection                */
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
INT  setsockopt(INT sockID, INT option_level, INT option_name, const VOID *option_value, INT option_length)
{
UINT            reuse_enabled;
NX_BSD_SOCKET   *bsd_socket_ptr;
ULONG           window_size;
ULONG           timer_ticks;
struct timeval *time_val;
INT             i;
struct ip_mreq *mreq;
UINT            mcast_interface;
UINT            status;


    /* Check for valid socket ID. */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Error, invalid socket ID.  */

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Check for invalid paremters. */
    if((option_value == NX_NULL) || (option_length == 0))        
    {

        /* Error, one or more invalid arguments.  */

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return NX_SOC_ERROR;
    }

    if (option_level == IPPROTO_IP)
    {

        if((option_name <= SO_MAX) ||  (option_name > IP_OPTION_MAX))
        {

            /* Error, one or more invalid arguments.  */

            /* Set the socket error if extended socket options enabled. */
            set_errno(ENOPROTOOPT);              
            
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return NX_SOC_ERROR;
        }
    }
    else if(option_level == SOL_SOCKET)
    {

        if((option_name > SO_MAX) ||
           (option_name < SO_MIN))
        {
            /* Error, one or more invalid arguments.  */
            
            /* Set the socket error if extended socket options enabled. */
            set_errno(ENOPROTOOPT);  
            
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return NX_SOC_ERROR;
        }
    }
    else
    {
        /* Error, one or more invalid arguments.  */

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return NX_SOC_ERROR;
    }
    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;

    /* Set up pointer to the BSD socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    /* Set the socket option status. */
    switch (option_name)
    {

        case SO_BROADCAST:

            /* This is the default behavior of NetX. All sockets have this capability. */
        break; 

        case SO_KEEPALIVE:

            /* Only available to TCP BSD sockets. */
            if (bsd_socket_ptr -> nx_bsd_socket_tcp_socket)
            {

                /* Verify TCP keep alive is built into the NetX library or return an error. */
#ifndef NX_ENABLE_TCP_KEEPALIVE

                /* Set the socket error if extended socket options enabled. */
                set_errno(ENOPROTOOPT);  

                /* Return an error status. */
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
#else
                /* Determine if NetX supports keepalive. */

                /* Update the BSD socket with this attribute. */
                bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_keepalive_enabled = 
                                        (UINT)(((struct sock_keepalive *)option_value) -> keepalive_enabled);

                if (bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_keepalive_enabled == NX_TRUE)
                {

                    /* Set the keep alive timeout for this socket with the NetX configurable keep alive timeout. */
                    bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_keepalive_timeout =  NX_TCP_KEEPALIVE_INITIAL;
                }
                else
                {

                    /* Clear the socket keep alive timeout. */
                    bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_keepalive_timeout =  0;
                }
#endif /* NX_ENABLE_TCP_KEEPALIVE */
            }
            else
            {
                /* Not a TCP socket. */

                /* Set the socket error if extended socket options enabled. */
                set_errno(ENOPROTOOPT);  

                /* Return an error status. */
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }

        break;

        case SO_LINGER:

            /* The Linger socket option is not supported in NetX BSD. */

            return NX_NOT_ENABLED;

        case SO_SNDTIMEO:

            time_val =  (struct timeval *)option_value;

            /* Calculate ticks for the ThreadX Timer.  */
            timer_ticks = (ULONG)(time_val -> tv_usec)/NX_MICROSECOND_PER_CPU_TICK  + (ULONG)(time_val -> tv_sec) * NX_IP_PERIODIC_RATE;

            bsd_socket_ptr -> nx_bsd_option_send_timeout = timer_ticks;

        break;

        case SO_RCVTIMEO:

            time_val =  (struct timeval *)option_value;

            /* Calculate ticks for the ThreadX Timer.  */
            timer_ticks = (ULONG)(time_val -> tv_usec)/NX_MICROSECOND_PER_CPU_TICK  + (ULONG)(time_val -> tv_sec) * NX_IP_PERIODIC_RATE;

            bsd_socket_ptr -> nx_bsd_option_receive_timeout = timer_ticks;

        break;

        case SO_RCVBUF:

            /* Only available to TCP sockets. */
            if (!bsd_socket_ptr -> nx_bsd_socket_tcp_socket)
            {

                /* Set the socket error if extended socket options enabled. */
                set_errno(ENOPROTOOPT);  

                /* Return an error status. */
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }


            window_size = (ULONG)(((struct sock_winsize *)option_value) -> winsize);

#ifdef NX_ENABLE_TCP_WINDOW_SCALING


            /* If Window scaling feature is enabled, record this user-specified window size. */
            bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_rx_window_maximum = window_size;
#else
            /* Otherwise the windows size limit is applied. */
            if(window_size > 65535)
                window_size = 65535;

#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

            /* Setup the sliding window information.  */
            bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_rx_window_default =   window_size;
            bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_rx_window_current =   window_size;

        break;

        case SO_REUSEADDR:

            reuse_enabled = (UINT)(((struct sock_reuseaddr *)option_value) -> reuseaddr_enabled);

            if(reuse_enabled)
                bsd_socket_ptr -> nx_bsd_socket_option_flags |= NX_BSD_SOCKET_ENABLE_OPTION_REUSEADDR;
            else
                bsd_socket_ptr -> nx_bsd_socket_option_flags &= (ULONG)(~NX_BSD_SOCKET_ENABLE_OPTION_REUSEADDR);

        break;
                   

        case TCP_NODELAY:

            /* This is the default behavior of NetX. All sockets have this attribute. */

        break; 

        case IP_MULTICAST_TTL:

            /* Validate the option length. */
            if(option_length != sizeof(UCHAR))
            {

                /* Set the socket error if extended socket options enabled. */
                set_errno(EINVAL);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }
          
            /* Verify that the socket is still valid. */
            if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
            {

                /* Set the socket error if extended socket options enabled. */
                set_errno(EBADF);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }

            /* Make sure socket is UDP type. */
            if(bsd_socket_ptr -> nx_bsd_socket_udp_socket == NX_NULL)
            {
                /* Set the socket error if extended socket options enabled. */
                set_errno(ENOPROTOOPT);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }
            /* Set the TTL value. */
            bsd_socket_ptr -> nx_bsd_socket_udp_socket -> nx_udp_socket_time_to_live = *(UCHAR*)option_value;
        break;

            


        case IP_ADD_MEMBERSHIP:
        case IP_DROP_MEMBERSHIP:

            /* Validate the option length */
            if(option_length != sizeof(struct ip_mreq))
            {

                /* Set the socket error if extended socket options enabled. */
                set_errno(EINVAL);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }
            
            mreq = (struct ip_mreq*)option_value;

            /* Make sure the multicast group address is valid. */
            if((mreq -> imr_multiaddr.s_addr & ntohl(NX_IP_CLASS_D_TYPE)) != ntohl(NX_IP_CLASS_D_TYPE))
            {
                /* Set the socket error if extended socket options enabled. */
                set_errno(EINVAL);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }

            /* Verify that the socket is still valid. */
            if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
            {
                /* Set the socket error if extended socket options enabled. */
                set_errno(EBADF);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }

            /* Make sure socket is UDP type. */
            if(bsd_socket_ptr -> nx_bsd_socket_udp_socket == NX_NULL)
            {
                /* Set the socket error if extended socket options enabled. */
                set_errno(ENOPROTOOPT);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }

            /* Validate that the interface is one of the local IPv4 interfaces. */
            /* We allow imr_interface being zero to indicate the primary interface. */
            mcast_interface = NX_MAX_IP_INTERFACES;

            if(mreq -> imr_interface.s_addr == INADDR_ANY)
            {
                mcast_interface = 0;
            }
            else 
            {   

                /* Set the socket error if extended socket options enabled. */
                UINT addr;

                /* Convert the local interface value to host byte order. */
                addr = ntohl(mreq -> imr_interface.s_addr);

                /* Search through the interface table for a matching one. */
                for(i = 0; i < NX_MAX_IP_INTERFACES; i++)
                {

                    if(addr == nx_bsd_default_ip -> nx_ip_interface[i].nx_interface_ip_address)
                    {

                        mcast_interface = (UINT)i;
                        break;
                    }
                }
            }

            if(mcast_interface == NX_MAX_IP_INTERFACES)
            {

                /* Did not find a matching interface. */
                set_errno(EINVAL);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }
            
            if(option_name == IP_ADD_MEMBERSHIP)
            {

                /* Make sure the IGMP feature is enabled. */
                if(nx_bsd_default_ip -> nx_ip_igmp_packet_receive == NX_NULL)
                {
                    nx_igmp_enable(nx_bsd_default_ip);
                }
                    
                /* Join the group. */
                status = nx_igmp_multicast_interface_join(nx_bsd_default_ip, ntohl(mreq -> imr_multiaddr.s_addr), mcast_interface);
            }
            else
            {

                /* Leave group */
                status = nx_igmp_multicast_leave(nx_bsd_default_ip, ntohl(mreq -> imr_multiaddr.s_addr));
            }

            if(status != NX_SUCCESS)
            {

                set_errno(EINVAL);  
                
                NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
                return NX_SOC_ERROR;
            }                                                      

            break;


        default:

            /* Set the socket error if extended socket options enabled. */
            set_errno(EINVAL);  

            /* Return an error status. */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return NX_SOC_ERROR;
    }

    /* Socket option successfully updated. */
    return NX_SUCCESS;
}


/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    getsockname                                         PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*    This function returns the socket's primary interface address and    */
/*    port. For NetX environments, it returns the address at address      */
/*    index 1 into the IP address table; this is where the primary        */
/*    interface global IP address is normally located.                    */
/*                                                                        */
/*  INPUT                                                                 */  
/*                                                                        */  
/*    sockID                                socket descriptor             */
/*    localAddress                          sockaddr struct to return     */
/*                                          the local address             */
/*    addressLength                         Number of bytes in sockAddr   */
/*                                                                        */
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    NX_SOC_OK (0)                         On success                    */
/*    NX_SOC_ERROR (-1)                     On failure                    */
/*                                                                        */  
/*  CALLS                                                                 */  
/*                                                                        */  
/*    tx_mutex_get                          Get protection                */ 
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
/*  09-30-2020     Yuxin Zhou               Modified comment(s), and      */
/*                                            verified memcpy use cases,  */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
INT  getsockname(INT sockID, struct sockaddr *localAddress, INT *addressLength)
{

struct sockaddr_in  soc_struct;
UINT                status;
NX_BSD_SOCKET       *bsd_socket_ptr;


    /* Check whether supplied socket ID is valid.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    if((localAddress == NX_NULL) || (addressLength == NX_NULL) || (*addressLength == 0))
    {
    
        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        /* Return error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;

    /* Setup pointer to socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    /* Get the protection mutex.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status)
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);  

        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Is the socket still in use?  */
    if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
    {

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
        
        /* Return error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }        
    
    if(!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_BOUND))
    {
        /* This socket is not bound yet.  Just return.
           According to the spec, if the socket is not bound, the value stored in
           localAddress is unspecified. */
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
        
        /* Success!  */    
        return(NX_SOC_OK);
    }

    if(bsd_socket_ptr -> nx_bsd_socket_family == AF_INET)
    {
        if(bsd_socket_ptr -> nx_bsd_socket_local_bind_interface == NX_BSD_LOCAL_IF_INADDR_ANY)
        {
            soc_struct.sin_addr.s_addr = INADDR_ANY;
        }
        else if(bsd_socket_ptr -> nx_bsd_socket_local_bind_interface == 0)
        {

            set_errno(EINVAL);

            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);
            
            /* Return error.  */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR);
        }
        else
        {
            NX_INTERFACE* local_if = (NX_INTERFACE*)(bsd_socket_ptr -> nx_bsd_socket_local_bind_interface);
            soc_struct.sin_addr.s_addr = htonl(local_if -> nx_interface_ip_address);
        }
        soc_struct.sin_port = htons((USHORT)bsd_socket_ptr -> nx_bsd_socket_local_port);
        
        soc_struct.sin_family = AF_INET;

        if((*addressLength) > (INT)sizeof(struct sockaddr_in))
        {
            *addressLength = sizeof(struct sockaddr_in);
        }
        memcpy(localAddress, &soc_struct, (UINT)(*addressLength)); /* Use case of memcpy is verified. */
    }
    else
    {
    
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        set_errno(EPROTONOSUPPORT);

        /* Return error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }



    /* Release the protection mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);
    
    /* Success!  */    
    return(NX_SOC_OK);
}


/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    getpeername                                         PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*    This function returns the socket's remote address and port.         */
/*                                                                        */
/*  INPUT                                                                 */  
/*                                                                        */
/*    sockID                                socket descriptor             */
/*    localAddress                          sockaddr struct to return     */
/*                                          the remote address            */
/*    addressLength                         Number of bytes in sockAddr   */
/*                                                                        */
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    NX_SOC_OK (0)                         On success                    */
/*    NX_SOC_ERROR (-1)                     On failure                    */
/*                                                                        */  
/*  CALLS                                                                 */  
/*                                                                        */  
/*    tx_mutex_get                          Get protection                */ 
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
INT  getpeername(INT sockID, struct sockaddr *remoteAddress, INT *addressLength)
{

UINT                status;
NX_BSD_SOCKET       *bsd_socket_ptr;
struct sockaddr_in  *soc_struct_ptr = NX_NULL;


    /* Check whether supplied socket ID is valid.  */
    if ((sockID < NX_BSD_SOCKFD_START) || (sockID >= (NX_BSD_SOCKFD_START + NX_BSD_MAX_SOCKETS)))
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        /* Error, invalid socket ID.  */
        NX_BSD_ERROR(ERROR, __LINE__);
        return(ERROR);
    }

    /* Normalize the socket ID.  */
    sockID =  sockID - NX_BSD_SOCKFD_START;

    /* Check the remote address and length pointers.  */
    if((remoteAddress == NX_NULL) ||(addressLength == NX_NULL))
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        /* Return error.  */
        NX_BSD_ERROR(ERROR, __LINE__);
        return(ERROR);
    }


    /* Get the protection mutex.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status)
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);  

        /* Error getting the protection mutex.  */
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(ERROR); 
    }

    /* Setup pointer to socket.  */
    bsd_socket_ptr =  &nx_bsd_socket_array[sockID];

    if(bsd_socket_ptr -> nx_bsd_socket_family == AF_INET)
    {        

        /* This is an IPv4 only socket. */

        /* Now validate the size of remoteAddress structure. */
        if(*addressLength < (INT)sizeof(struct sockaddr_in))
        {

            /* User supplied buffer is too small .*/

            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            /* Set the socket error, if socket enabled with extended BSD features. */
            set_errno(ESOCKTNOSUPPORT);

            /* Return error.  */
            NX_BSD_ERROR(ERROR, __LINE__);
            return(ERROR);
        }
        
        soc_struct_ptr = (struct sockaddr_in*)remoteAddress;
        *addressLength = sizeof(struct sockaddr_in);
    }
    else
    {

        /* Not a valid address family. */
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error, if socket enabled with extended BSD features. */
        set_errno(ESOCKTNOSUPPORT);

        /* Return error.  */
        NX_BSD_ERROR(ERROR, __LINE__);
        return(ERROR);
    }

    /* Is the socket still in use?  */
    if (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
    {

        /* Error, socket not in use anymore.  */
        
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error if extended options enabled. */
        set_errno(EBADF);

        /* Return error.  */
        NX_BSD_ERROR(ERROR, __LINE__);
        return(ERROR);
    }        

    /* Check whether TCP or UDP */
    if (bsd_socket_ptr -> nx_bsd_socket_tcp_socket)
    {
        
        /* TCP Socket.  Determine socket family type. */
        if(bsd_socket_ptr -> nx_bsd_socket_family == AF_INET)
        {

            soc_struct_ptr -> sin_family      =  AF_INET;
            soc_struct_ptr -> sin_port        =  htons((USHORT)bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_connect_port);
            soc_struct_ptr -> sin_addr.s_addr =  htonl(bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_connect_ip);
        }
        else
        {
        
            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            /* Set the socket error if extended options enabled. */
            set_errno(EBADF);

            /* Return error.  */
            NX_BSD_ERROR(ERROR, __LINE__);
            return(ERROR);            

        }
    }
    else if (bsd_socket_ptr -> nx_bsd_socket_udp_socket)
    {
    
        /* UDP Socket.  Get Peer Name doesn't apply to UDP sockets.  Only fill in AF family information.*/
        if(bsd_socket_ptr -> nx_bsd_socket_family == AF_INET)
        {
            soc_struct_ptr -> sin_family      =  AF_INET;
            soc_struct_ptr -> sin_port        =  0;
            soc_struct_ptr -> sin_addr.s_addr =  0; 
        }
        else
        {

            /* Release the protection mutex.  */
            tx_mutex_put(nx_bsd_protection_ptr);

            /* Set the socket error, if socket enabled with extended BSD features. */
            set_errno(ESOCKTNOSUPPORT);

            /* Return error.  */
            NX_BSD_ERROR(ERROR, __LINE__);
            return(ERROR);            

        }
    }
    else
    {
    
        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);

        /* Set the socket error, if socket enabled with extended BSD features. */
        set_errno(ESOCKTNOSUPPORT);

        /* Return error.  */
        NX_BSD_ERROR(ERROR, __LINE__);
        return(ERROR);
    }


    /* Release the protection mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);
    
    /* Success!  */    
    return(NX_SOC_OK);
}

/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    select                                              PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*    This function allows for sockets to be checked for incoming packets.*/
/*    nfds should be one greater than value of the largest valued socket  */
/*    descriptor in any of the lists. If you don't wish to calculate this,*/
/*    use FD_SETSIZE instead.For small numbers of sockets,select() will be*/
/*    less efficient if FD_SETSIZE is passed.If the bit corresponding to  */
/*    a socket in an fd_set is set,that socket will be checked for the    */
/*    condition the fd_set corresponds to.If the condition they are       */
/*    checked for is true, they will still be set to true when select()   */
/*    returns (otherwise they will be set to false).                      */
/*    Note that the sets are modified by select():thus they must be reset */
/*    between each call to the function.                                  */
/*                                                                        */     
/*    fd_sets can be manipulated using the following macros or functions: */
/*                                                                        */
/*    FD_SET(fd, fdset)  Sets socket fd in fdset to true.                 */
/*    FD_CLR(fd, fdset)  Sets socket fd in fdset to false.                */
/*    FD_ISSET(fd, fdset)Returns true if socket fd is set to true in fdset*/
/*    FD_ZERO(fdset)  Sets all the sockets in fdset to false.             */ 
/*                                                                        */
/*    If the input timeout is NULL, select() blocks until one of the      */
/*    sockets receives a packet. If the timeout is non-NULL, select waits */
/*    for the specified time and returns regardless if any socket has     */
/*    received a packet.  Otherwise as soon as a socket receives a packet */
/*    this function will return immediately.                              */
/*                                                                        */
/*    To use select() in non-blocking mode call it with a non-null timeout*/
/*    input but set tv_sec and tv_usec to zero, in Unix fashion.          */
/*                                                                        */
/*    select() returns the number of sockets for which the specified      */
/*    conditions are true. If it encounters an error, it will return -1.  */
/*                                                                        */
/*    NOTE:  ****** When select returns NX_SOC_ERROR it won't update      */
/*           the readfds descriptor.                                      */
/*                                                                        */   
/*  INPUT                                                                 */  
/*                                                                        */   
/*    nfds                                 Maximum socket descriptor #    */
/*    fd_set *readFDs                      List of read ready sockets     */
/*    fd_set *writeFDs                     List of write ready sockets    */
/*    fd_set *exceptFDs                    List of exceptions             */
/*    struct timeval *timeOut                                             */
/*                                                                        */  
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    NX_SUCCESS                            No descriptors read           */
/*                                             (successful completion)    */
/*    status                                Number of descriptors read    */
/*                                             (< 0 if error occurred)    */
/*                                                                        */ 
/*  CALLS                                                                 */  
/*                                                                        */  
/*    FD_ZERO                               Clear a socket ready list     */
/*    FD_ISSET                              Check a socket is ready       */
/*    FD_SET                                Set a socket to check         */ 
/*    nx_tcp_socket_receive                 Receive TCP packet            */ 
/*    nx_udp_source_extract                 Extract source IP and port    */ 
/*    tx_event_flags_get                    Get events                    */ 
/*    tx_mutex_get                          Get protection                */ 
/*    tx_mutex_put                          Release protection            */ 
/*    tx_thread_identify                    Get current thread pointer    */ 
/*    tx_thread_preemption_change           Disable/restore preemption    */ 
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
INT  select(INT nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{

INT                     i;
UINT                    status;
NX_BSD_SOCKET_SUSPEND   suspend_request;
NX_PACKET               *packet_ptr;
fd_set                  readfds_found;
fd_set                  writefds_found;
fd_set                  exceptfds_found;
INT                     readfds_left;
INT                     writefds_left;
INT                     exceptfds_left;
ULONG                   ticks;
UINT                    original_threshold;
TX_THREAD               *current_thread_ptr;
INT                     ret;


    /* Check for valid input parameters.  */
    if ((readfds == NX_NULL) && (writefds == NX_NULL) && (exceptfds == NX_NULL) && (timeout == NX_NULL))
    {
    
        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Check the maximum number of file descriptors.  */
    if((nfds < (NX_BSD_SOCKFD_START + 1)) || (nfds >= (NX_BSD_MAX_SOCKETS + NX_BSD_SOCKFD_START + 1)))
    {

        /* Set the socket error */
        set_errno(EBADF);

        /* Return an error.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    /* Clear the read and the write selector set.  */
    FD_ZERO(&readfds_found);
    FD_ZERO(&writefds_found);
    FD_ZERO(&exceptfds_found);

    if(readfds)
        readfds_left = readfds -> fd_count;
    else
        readfds_left = 0;

    if(writefds)
    {
    
        writefds_left = writefds -> fd_count;
    }
    else
    {
    
        writefds_left = 0;
    }

    if(exceptfds)
    {

        exceptfds_left = exceptfds -> fd_count;
    }
    else
    {
    
        exceptfds_left = 0;
    }

    /* Compute the timeout for the suspension if a timeout value was supplied.  */
    if (timeout != NX_NULL) 
    {
        
        /* Calculate ticks for the ThreadX Timer.  */
        ticks = (ULONG)(timeout -> tv_usec)/NX_MICROSECOND_PER_CPU_TICK + (ULONG)(timeout -> tv_sec) * NX_IP_PERIODIC_RATE;
    }
    else
    {
    
        /* If no timeout input, set the wait to 'forever.'  */
        ticks =  TX_WAIT_FOREVER;
    }

    /* Get the protection mutex.  */
    status =  tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);  

        /* Set the socket error. */
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }
       
    /* Loop through the BSD sockets to see if the read ready request can be satisfied.  */
    for (i = 0; i < (nfds - NX_BSD_SOCKFD_START); i++)
    {

        if((readfds == NX_NULL) || (readfds_left == 0))
            break;

        /* Is this socket selected for read?  */
        if (FD_ISSET((i + NX_BSD_SOCKFD_START), readfds))
        {

            /* Yes, decrement the number of read selectors left to search for.  */
            readfds_left--;

            /* Is this BSD socket in use?  */
            if (!(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
            {

                /* There is; add this socket to the read ready list.  */
                FD_SET(i + NX_BSD_SOCKFD_START, &readfds_found);
            }

            /* Check to see if there is a disconnection request pending.  */
            else if (nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_DISCONNECTION_REQUEST)
            {
            
                /* There is; add this socket to the read ready list.  */
                FD_SET(i + NX_BSD_SOCKFD_START, &readfds_found);
            }

            /* Check to see if there is a receive packet pending.  */ 
            else if (nx_bsd_socket_array[i].nx_bsd_socket_received_packet)
            {
            
                /* Therer is; add this socket to the read ready list.  */
                FD_SET(i + NX_BSD_SOCKFD_START, &readfds_found);
            }
            /* Is this a TCP socket? */
            else if (nx_bsd_socket_array[i].nx_bsd_socket_tcp_socket)
            {
                /* Check if this is a master socket and if its associated secondary socket
                    is connected. If it is, the master socket should be considered readable. */
                if(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_MASTER_SOCKET)
                {

                    if(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_ENABLE_LISTEN)
                    {

                        /* If the secondary socket does not exist, try to allocate one. */
                        if(nx_bsd_socket_array[i].nx_bsd_socket_union_id.nx_bsd_socket_secondary_socket_id >= NX_BSD_MAX_SOCKETS)
                        {

                            /* This secondary socket is not avaialble yet.  This could happen if the
                               previous accept call fails to allocate a new secondary socket. */
                            ret = nx_bsd_tcp_create_listen_socket(i, 0);
                            
                            if(ret < 0)
                            {

                                /* Mark the FD set so the application could be notified. */
                                FD_SET(i + NX_BSD_SOCKFD_START, &readfds_found);
                            }
                        }

                        if(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED)
                        {
                            FD_SET(i + NX_BSD_SOCKFD_START, &readfds_found);
                        }
                    }
                }
                else if(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED)
                {

                    /* Yes; attempt to perform a non-blocking read.  */
                    status =  nx_tcp_socket_receive(nx_bsd_socket_array[i].nx_bsd_socket_tcp_socket, &packet_ptr, TX_NO_WAIT);

                    /* Check for success.  */
                    if (status == NX_SUCCESS)
                    {

                        /* Save the received packet in the TCP BSD socket packet pointer.  */
                        nx_bsd_socket_array[i].nx_bsd_socket_received_packet =  packet_ptr;
                    
                        /* Reset the packet offset.  */
                        nx_bsd_socket_array[i].nx_bsd_socket_received_packet_offset =  0;

                        /* Increase the received count. */
                        nx_bsd_socket_array[i].nx_bsd_socket_received_byte_count += packet_ptr -> nx_packet_length;
                        nx_bsd_socket_array[i].nx_bsd_socket_received_packet_count++;

                        /* Add this socket to the read ready list.  */
                        FD_SET(i + NX_BSD_SOCKFD_START, &readfds_found);
                    }
                }
            }

        }
    }
    /* Loop through the BSD sockets to see if the write ready request can be satisfied.  */
    for(i = 0; i < (nfds - NX_BSD_SOCKFD_START); i++)
    {

        if((writefds == NX_NULL) || (writefds_left == 0))
            break;

        /* Is this socket selected for write?  */
        if (FD_ISSET(i + NX_BSD_SOCKFD_START, writefds))
        {

            /* Yes, decrement the number of read selectors left to search for.  */
            writefds_left--;

            /* Is this BSD socket in use?  */
            if (!(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
            {

                /* Yes, add this socket to the write ready list.  */
                FD_SET(i + NX_BSD_SOCKFD_START, &writefds_found);
            }

            /* Check to see if there is a connection request pending.  */
            else if (nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTION_REQUEST)
            {
            
                /* Yes, add this socket to the write ready list.  */
                FD_SET(i + NX_BSD_SOCKFD_START, &writefds_found);
            }

            /* Check to see if there is an error.*/
            else if (nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR)
            {

                FD_SET(i + NX_BSD_SOCKFD_START, &writefds_found);
            }
        }
    }

    /* Loop through the BSD sockets to see if the exception request can be satisfied.  */
    for(i = 0; i < (nfds - NX_BSD_SOCKFD_START); i++)
    {

        if((exceptfds == NX_NULL) || (exceptfds_left == 0))
            break;

        /* Is this socket selected for exceptions?  */
        if (FD_ISSET(i + NX_BSD_SOCKFD_START, exceptfds))
        {

            /* Yes, decrement the number of read selectors left to search for.  */
            exceptfds_left--;

            /* Is this BSD socket in use?  */
            if (!(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
            {

                FD_SET(i + NX_BSD_SOCKFD_START, &exceptfds_found);
            }

            /* Check to see if there is an error.*/
            else if(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_ERROR)
            {

                FD_SET(i + NX_BSD_SOCKFD_START, &exceptfds_found);
            }
        }
    }

    /* Now determine if we have found anything that satisfies the select request.  */
    if (readfds_found.fd_count || writefds_found.fd_count || exceptfds_found.fd_count)
    {

        /* Yes, return what we have and we're done.   */

        /* Copy over the requested read ready fds.  */
        if(readfds)
            *readfds =  readfds_found;

        if(writefds)
            *writefds = writefds_found;

        if(exceptfds)
            *exceptfds = exceptfds_found;

        /* Release the protection mutex.  */
        tx_mutex_put(nx_bsd_protection_ptr);
        
        /* Return the number of fds found.  */
        return(readfds_found.fd_count + writefds_found.fd_count + exceptfds_found.fd_count);
    }

    /* Otherwise, nothing is ready to be read at this point.  */
    
    /* Pickup the current thread.  */
    current_thread_ptr =  tx_thread_identify();

    /* Save the fd requests in the local suspension structure. This will be used by the receive notify routines to 
       wakeup threads on the select.  */
    suspend_request.nx_bsd_socket_suspend_actual_flags =  0;

    if(readfds)
        suspend_request.nx_bsd_socket_suspend_read_fd_set =  *readfds;
    else
        FD_ZERO(&suspend_request.nx_bsd_socket_suspend_read_fd_set);

    if(writefds)
        suspend_request.nx_bsd_socket_suspend_write_fd_set = *writefds;
    else
        FD_ZERO(&suspend_request.nx_bsd_socket_suspend_write_fd_set);

    if(exceptfds)
        suspend_request.nx_bsd_socket_suspend_exception_fd_set = *exceptfds;
    else
        FD_ZERO(&suspend_request.nx_bsd_socket_suspend_exception_fd_set);
    
    /* Temporarily disable preemption.  */
    tx_thread_preemption_change(current_thread_ptr, 0, &original_threshold);
       
    /* Release the protection mutex.  */
    tx_mutex_put(nx_bsd_protection_ptr);

    status =  tx_event_flags_get(&nx_bsd_events, NX_BSD_SELECT_EVENT, TX_OR_CLEAR, (ULONG *) &suspend_request, ticks);

    /* Restore original preemption threshold.  */
    tx_thread_preemption_change(current_thread_ptr, original_threshold, &original_threshold);
        
    /* Check for an error.  */
    if (status != NX_SUCCESS)
    {

        /* If we got here, we received no packets. */

        /* TX_NO_EVENT implies an immediate return from the flag get call. 
           This happens if the wait option is set to zero. */
        if (status == TX_NO_EVENTS)
        {

            /* Determine if the effected sockets are non blocking (zero ticks for the wait option). */
            if (ticks == 0)
                set_errno(EWOULDBLOCK);  
            else
                set_errno(ETIMEDOUT);

            /* Do not handle as an error; just a timeout so return 0.  */
            return(0);
        }
        else
        {
        
            /* Actual error.  */
            /* Set the socket error if extended socket options enabled. */
            set_errno(EINVAL);

            /* Error getting the protection mutex.  */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR); 
        }
    }
    else
    {

        /* Otherwise, a receive event has been found. Simply copy the receive events.  */
        if(readfds)
            *readfds =  suspend_request.nx_bsd_socket_suspend_read_fd_set;
        if(writefds)
            *writefds = suspend_request.nx_bsd_socket_suspend_write_fd_set;
        if(exceptfds)
            *exceptfds = suspend_request.nx_bsd_socket_suspend_exception_fd_set;

        /* Return the number of fds.  */
        return(suspend_request.nx_bsd_socket_suspend_read_fd_set.fd_count + 
               suspend_request.nx_bsd_socket_suspend_write_fd_set.fd_count +
               suspend_request.nx_bsd_socket_suspend_exception_fd_set.fd_count);
    }


}



/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_tcp_receive_notify                           PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This is the NetX callback function for TCP Socket receive operation */
/*    This function resumes all the threads suspended on the socket.      */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    *socket_ptr                           Pointer to the socket which   */
/*                                            received the data packet    */  
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    FD_ZERO                               Clear a socket ready list     */
/*    FD_ISSET                              Check a socket is ready       */
/*    FD_SET                                Set a socket to check         */ 
/*    tx_event_flags_get                    Get events                    */ 
/*    tx_mutex_get                          Get protection                */ 
/*    tx_mutex_put                          Release protection            */ 
/*    tx_thread_identify                    Get current thread pointer    */ 
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX                                                                */ 
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
static VOID  nx_bsd_tcp_receive_notify(NX_TCP_SOCKET *socket_ptr)
{
UINT                    bsd_socket_index;

    /* Figure out what BSD socket this is.  */
    bsd_socket_index =  (UINT) socket_ptr -> nx_tcp_socket_reserved_ptr;
    
    /* Determine if this is a good index into the BSD socket array.  */
    if (bsd_socket_index >= NX_BSD_MAX_SOCKETS)
    {
    
        /* Bad socket index... simply return!  */
        return;
    }

    /* Now check if the socket may have been released (e.g. socket closed) while
       waiting for the mutex. */
    if( socket_ptr -> nx_tcp_socket_id == 0 )    
    {

        return;          
    }     

    /* Check the suspended socket list for one ready to receive or send packets. */
    nx_bsd_select_wakeup(bsd_socket_index, FDSET_READ);


    return;
}


/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_tcp_establish_notify                         PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This is the NetX callback function for TCP Server Socket listen.    */
/*    This function resumes all the threads suspended on the socket.      */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    *socket_ptr                           Pointer to the socket which   */
/*                                          Received the data packet      */  
/*                                                                        */
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    FD_ZERO                               Clear a socket ready list     */
/*    FD_ISSET                              Check a socket is ready       */
/*    FD_SET                                Set a socket to check         */ 
/*    tx_event_flags_get                    Get events                    */ 
/*    tx_mutex_get                          Get protection                */ 
/*    tx_mutex_put                          Release protection            */ 
/*    tx_thread_identify                    Get current thread pointer    */ 
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX                                                                */ 
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
#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
static VOID  nx_bsd_tcp_establish_notify(NX_TCP_SOCKET *socket_ptr)
{
UINT                    bsd_socket_index;
UINT                    master_socket_index; 

    /* Figure out what BSD socket this is.  */
    bsd_socket_index =  (UINT) socket_ptr -> nx_tcp_socket_reserved_ptr;
    
    /* Determine if this is a good index into the BSD socket array.  */
    if (bsd_socket_index >= NX_BSD_MAX_SOCKETS)
    {
    
        /* Bad socket index... simply return!  */
        return;
    }

    /* Initialize the master socket index to an invalid value so we can check if it was actually used
       later.  */
    master_socket_index =  NX_BSD_MAX_SOCKETS;

    /* Mark the socket as connected, and also clear the EINPROGRESS flag */
    nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTED;

    nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_status_flags |=  NX_BSD_SOCKET_CONNECTION_REQUEST;

    /* Reset the listen-enabled flag. */
    nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_ENABLE_LISTEN);

    /* Mark the socket is bound. */
    nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_status_flags |= NX_BSD_SOCKET_BOUND;

    /* Find out the local address this socket is connected on. */
    if(nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_family == AF_INET)
    {
        /* IPv4 case */
        nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_local_bind_interface = (ULONG)socket_ptr -> nx_tcp_socket_connect_interface;
    }
    /* Determine if the BSD socket is server socket. */


    /* Is this a secondary socket? */
    if (nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_SECONDARY_SOCKET)
    {

        /* Yes, get the master socket.  */
        master_socket_index =  (UINT)(nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_union_id.nx_bsd_socket_master_socket_id);

        /* Mark the server socket as also connected. */
        nx_bsd_socket_array[master_socket_index].nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTED;

        nx_bsd_socket_array[master_socket_index].nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTION_REQUEST;

        /* Check on connect requests for all server sockets for this master socket. */
        nx_bsd_select_wakeup(master_socket_index, FDSET_READ);
    }
    else
    {
        /* This is a client socket. */
        nx_bsd_select_wakeup(bsd_socket_index, FDSET_WRITE);
    }
}
#endif /* NX_DISABLE_EXTENDED_NOTIFY_SUPPORT */

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_tcp_socket_disconnect_notify                 PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This is the NetX callback function for TCP Socket disconnect.       */
/*    This function resumes all the BSD threads suspended on the socket.  */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    *socket_ptr                           Pointer to the socket which   */
/*                                            received the data packet    */  
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    FD_ZERO                               Clear a socket ready list     */
/*    FD_ISSET                              Check a socket is ready       */
/*    FD_SET                                Set a socket to check         */ 
/*    tx_event_flags_get                    Get events                    */ 
/*    tx_mutex_get                          Get protection                */ 
/*    tx_mutex_put                          Release protection            */ 
/*    tx_thread_identify                    Get current thread pointer    */ 
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX                                                                */ 
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
static VOID  nx_bsd_tcp_socket_disconnect_notify(NX_TCP_SOCKET *socket_ptr)
{

UINT                    bsd_socket_index;
UINT                    master_socket_index;
NX_BSD_SOCKET          *bsd_socket_ptr;
UINT                    status;


    /* Figure out what BSD socket this is.  */
    bsd_socket_index =  (UINT) socket_ptr -> nx_tcp_socket_reserved_ptr;
    
    /* Determine if this is a good index into the BSD socket array.  */
    if (bsd_socket_index >= NX_BSD_MAX_SOCKETS)
    {
        /* No good! */
        return;
    }

    bsd_socket_ptr = &nx_bsd_socket_array[bsd_socket_index];

    /* If the socket already received a disconnect request, no need to do anything here. */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_DISCONNECTION_REQUEST)
    {
        return;
    }
        
    /* Mark this socket as having a disconnect request pending.  */
    bsd_socket_ptr -> nx_bsd_socket_status_flags |=  NX_BSD_SOCKET_DISCONNECTION_REQUEST;

    /* Is the socket trying to make a connection? */
    if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTION_INPROGRESS)
    {

        /* Yes, clear the INPROGRESS flag. */
        bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_CONNECTION_INPROGRESS);

        /* If this is secondary server socket, there is no need to wake up the select call.  */
        if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_SECONDARY_SOCKET)
        {

             
            /* Instead the socket needs to be cleaned up and to perform a relisten. */
            if(!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED))
            {

                /* Turn off the disconnection_request flag. */
                bsd_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_DISCONNECTION_REQUEST);
                
                nx_tcp_server_socket_unaccept(bsd_socket_ptr -> nx_bsd_socket_tcp_socket);
                
                /* Check if a listen request is queued up for this socket. */
                nx_bsd_tcp_pending_connection(bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_port,
                                              bsd_socket_ptr -> nx_bsd_socket_tcp_socket);
            
                status = nx_tcp_server_socket_relisten(nx_bsd_default_ip, 
                                                       bsd_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_port,
                                                       bsd_socket_ptr -> nx_bsd_socket_tcp_socket);
                
                /* Force the socket into SYN_RECEIVED state */
                nx_tcp_server_socket_accept(bsd_socket_ptr -> nx_bsd_socket_tcp_socket, NX_NO_WAIT);

                if(status == NX_CONNECTION_PENDING)
                {

                    bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTION_INPROGRESS;
                }
                else if(status != NX_SUCCESS)
                {

                    /* Failed the relisten on the secondary socket.  Set the error code on the 
                       master socket, and wake it up. */
                    
                    master_socket_index = (UINT)(bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_master_socket_id;
                    
                    nx_bsd_socket_array[master_socket_index].nx_bsd_socket_status_flags |= NX_BSD_SOCKET_ERROR;
                    nx_bsd_set_error_code(&nx_bsd_socket_array[master_socket_index], status);
                    
                    nx_bsd_select_wakeup(master_socket_index, (FDSET_READ | FDSET_WRITE | FDSET_EXCEPTION));
                }
            }

        }
        else
        {

            /* Set error code. */
            bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_ERROR;
            bsd_socket_ptr -> nx_bsd_socket_error_code = ECONNREFUSED;
            
            /* Wake up the select on both read and write FDsets. */
            nx_bsd_select_wakeup(bsd_socket_index, (FDSET_READ | FDSET_WRITE | FDSET_EXCEPTION));
        }
    }
    else if(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED)
    {

        /* Wake up the select on both read and write FDsets. */
        nx_bsd_select_wakeup(bsd_socket_index, (FDSET_READ | FDSET_WRITE | FDSET_EXCEPTION));
    }
    else
    {

        /* In this case, connection reaches maximum retries or is refused by peer. */
        bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_ERROR;
        bsd_socket_ptr -> nx_bsd_socket_error_code = ENOTCONN;
    }

}



/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_udp_receive_notify                           PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This is the NetX callback function for UDP Socket receive           */ 
/*    operation.                                                          */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    *socket_ptr                           Pointer to the socket which   */
/*                                          Received the data packet      */  
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    FD_ZERO                               Clear a socket ready list     */
/*    FD_ISSET                              Check a socket is ready       */
/*    FD_SET                                Set a socket to check         */ 
/*    tx_event_flags_get                    Get events                    */ 
/*    tx_mutex_get                          Get protection                */ 
/*    tx_mutex_put                          Release protection            */ 
/*    tx_thread_identify                    Get current thread pointer    */ 
/*    nx_udp_socket_receive                 Receive UDP packet            */ 
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX                                                                */ 
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
static VOID  nx_bsd_udp_receive_notify(NX_UDP_SOCKET *socket_ptr)
{

UINT                    bsd_socket_index;
NX_PACKET               *packet_ptr;
NX_UDP_SOCKET           *udp_socket_ptr;    


    /* Figure out what BSD socket this is.  */
    bsd_socket_index =  ((UINT) socket_ptr -> nx_udp_socket_reserved_ptr) & 0x0000FFFF;
    
    /* Determine if this is a good index into the BSD socket array.  */
    if (bsd_socket_index >= NX_BSD_MAX_SOCKETS)
    {
        return;
    }

    udp_socket_ptr = nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_udp_socket;

    if (nx_udp_socket_receive(udp_socket_ptr, &packet_ptr, NX_NO_WAIT))
    {
        return;
    }

    nx_bsd_udp_packet_received((INT)bsd_socket_index, packet_ptr);

}


/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    FD_SET                                              PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*   This function adds a fd to the set.                                  */
/*                                                                        */  
/*  INPUT                                                                 */  
/*                                                                        */  
/*    fd                                    fd to add.                    */
/*    fd_set *fdset                         fd set.                       */
/*                                                                        */
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    None                                                                */  
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
VOID  FD_SET(INT fd, fd_set *fdset)
{

UINT    index;


    /* Check the FD size.  */
    if (fd >= NX_BSD_SOCKFD_START)
    {
    
        /* Normalize the fd.  */
        fd =  fd - NX_BSD_SOCKFD_START;
        
        /* Now make sure it isn't too big.  */
        if (fd < NX_BSD_MAX_SOCKETS)
        {

            /* Calculate the index into the bit map.  */
            index =  (UINT)fd/32;

            /* Now calculate the bit position.  */
            fd =  fd % 32;
            
            /* Is the bit already set?  */
            if ((fdset -> fd_array[index] & (((ULONG) 1) << fd)) == 0)
            {
    
                /* No, set the bit.  */
                fdset -> fd_array[index] = fdset -> fd_array[index] | (((ULONG) 1) << fd);
                
                /* Increment the counter.  */
                fdset -> fd_count++;
            }
        }
    }
}

/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    FD_CLR                                              PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*   This function removes a fd from a fd set.                            */
/*                                                                        */  
/*  INPUT                                                                 */  
/*                                                                        */  
/*    fd                                    fd to remove.                 */
/*    fd_set *fdset                         fd set.                       */
/*                                                                        */
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    None                                                                */
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
VOID  FD_CLR(INT fd, fd_set *fdset)
{

UINT    index;


    /* Check the FD size.  */
    if (fd >= NX_BSD_SOCKFD_START)
    {
    
        /* Normalize the fd.  */
        fd =  fd - NX_BSD_SOCKFD_START;
        
        /* Now make sure it isn't too big.  */
        if ((fd < NX_BSD_MAX_SOCKETS) && (fdset -> fd_count))
        {

            /* Calculate the index into the bit map.  */
            index =  (UINT)fd/32;

            /* Now calculate the bit position.  */
            fd =  fd % 32;
            
            /* Determine if the bit is set.  */
            if (fdset -> fd_array[index] & (((ULONG) 1) << fd))
            {
            
                /* Yes, clear the bit.  */
                fdset -> fd_array[index] = fdset -> fd_array[index] & ~(((ULONG) 1) << fd);
                
                /* Decrement the counter.  */
                fdset -> fd_count--;
            }
        }
    }
}


/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    FD_ISSET                                            PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*   This function tests to see if a fd is in the set.                    */
/*                                                                        */  
/*  INPUT                                                                 */  
/*                                                                        */  
/*    fd                                    fd to add.                    */
/*    fd_set *fdset                         fd set.                       */
/*                                                                        */
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    NX_TRUE                               If fd is found in the set.    */  
/*    NX_FALSE                              If fd is not there in the set.*/
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
INT  FD_ISSET(INT fd, fd_set *fdset)
{

UINT    index;


    /* Check the FD size.  */
    if (fd >= NX_BSD_SOCKFD_START)
    {
    
        /* Normalize the fd.  */
        fd =  fd - NX_BSD_SOCKFD_START;
        
        /* Now make sure it isn't too big.  */
        if (fd < NX_BSD_MAX_SOCKETS)
        {

            /* Calculate the index into the bit map.  */
            index =  (UINT)fd/32;

            /* Now calculate the bit position.  */
            fd =  fd % 32;
            
            /* Finally, see if the bit is set.  */
            if (fdset -> fd_array[index] & (((ULONG) 1) << fd))
            {
            
                /* Yes, return true!  */
                return(NX_TRUE);
            }
        }
    }

    /* Otherwise, return false.  */
    return(NX_FALSE);
}


/**************************************************************************/  
/*                                                                        */  
/*  FUNCTION                                               RELEASE        */  
/*                                                                        */  
/*    FD_ZERO                                             PORTABLE C      */  
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */  
/*                                                                        */
/*   This function clears a fd set.                                       */
/*                                                                        */  
/*  INPUT                                                                 */  
/*                                                                        */  
/*   fd_set *fdset                          fd set to clear.              */
/*                                                                        */
/*  OUTPUT                                                                */  
/*                                                                        */  
/*    None                                                                */  
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
VOID  FD_ZERO(fd_set *fdset)
{

INT     i;


    /* Clear the count.  */
    fdset -> fd_count =  0;

    /* Loop to clear the fd set.  */
    for (i = 0; i < (NX_BSD_MAX_SOCKETS+31)/32; i++)
    {
        /* Clear an entry in the array.  */
        fdset -> fd_array[i] =  0;
    }
}

 





/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_set_socket_timed_wait_callback               PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function is called when a BSD TCP socket has closed. If the    */
/*    BSD socket associated with the TCP socket is not enabled for        */
/*    REUSEADDR, this function will put the BSD socket in the TIMED WAIT  */
/*    state.                                                              */
/*                                                                        */ 
/*    When this time out expires, the BSD socket is removed from the TIME */
/*    WAIT State and available to the host application.                   */  
/*                                                                        */ 
/*    Note: only sockets not enabled with REUSEADDR are placed in the WAIT*/
/*    STATE. All other BSD sockets are immediately available upon closing.*/ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    tcp_socket_ptr                       TCP socket state being closed  */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    tx_thread_identify                   Identify socket owning thread  */ 
/*    tx_mutex_get                         Obtain BSD mutex protection    */ 
/*    tx_mutex_put                         Release BSD mutex protection   */
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX                                                                */ 
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
VOID  nx_bsd_socket_timed_wait_callback(NX_TCP_SOCKET *tcp_socket_ptr)
{
    NX_PARAMETER_NOT_USED(tcp_socket_ptr);

    /* Logic has been removed elsewhere but for compatibility with 
       NetX we leave this function stub. */

    return;
}



/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_packet_data_extract_offset                       PORTABLE C      */ 
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
/*    This basically defines the data extract service in the BSD source   */
/*    code if it is not provided in the NetX or NetX library already.     */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    packet_ptr                        Pointer to the source packet      */ 
/*    buffer_start                      Pointer to destination data area  */
/*    buffer_length                     Size in bytes                     */
/*    bytes_copied                      Number of bytes copied            */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    status                            Completion status                 */ 
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
/*  09-30-2020     Yuxin Zhou               Modified comment(s), and      */
/*                                            verified memcpy use cases,  */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
#ifdef NX_BSD_INCLUDE_DATA_EXTRACT_OFFSET
UINT  nx_packet_data_extract_offset(NX_PACKET *packet_ptr, ULONG offset, VOID *buffer_start, ULONG buffer_length, ULONG *bytes_copied)
{

ULONG       remaining_bytes;
UCHAR       *source_ptr;
UCHAR       *destination_ptr;
ULONG       offset_bytes;
ULONG       packet_fragment_length;
ULONG       bytes_to_copy;
NX_PACKET   *working_packet_ptr;

    working_packet_ptr =  packet_ptr;

    /* Check for an invalid offset or packet length.  */
    if(offset >= working_packet_ptr -> nx_packet_length)
    {
        /* Note: A zero offset with a packet of zero length is ok. */
        if ((offset == 0) && (working_packet_ptr -> nx_packet_length == 0))
        {
            *bytes_copied = 0;
            return(NX_SUCCESS);
        }

        /* Otherwise, this is an invalid offset or packet length. */
        return(NX_PACKET_OFFSET_ERROR);        
    }

    /* Initialize the source pointer to NULL.  */
    source_ptr =  NX_NULL;

    /* Traverse packet chain to offset.  */
    offset_bytes =  offset;
    while (working_packet_ptr)
    {     
        packet_fragment_length =  (working_packet_ptr -> nx_packet_append_ptr - working_packet_ptr -> nx_packet_prepend_ptr) ;

        /* Determine if we are at the offset location fragment in the packet chain  */
        if (packet_fragment_length > offset_bytes)
        {
            /* Setup loop to copy from this packet.  */
            source_ptr =  working_packet_ptr -> nx_packet_prepend_ptr + offset_bytes;

            /* Yes, get out of this  loop.  */
            break;
        }

        /* Decrement the remaining offset bytes*/
        offset_bytes = offset_bytes - packet_fragment_length ;

        /* Move to next packet.  */
        working_packet_ptr =  working_packet_ptr -> nx_packet_next;
    }

    /* Check for a valid source pointer.  */
    if (source_ptr == NX_NULL)
        return(NX_PACKET_OFFSET_ERROR);

    /* Setup the destination pointer.  */
    destination_ptr =  buffer_start;
    bytes_to_copy =   (packet_ptr->nx_packet_length - offset);

    /* Pickup the amount of bytes to copy.  */
    if( bytes_to_copy < buffer_length)
    {
        *bytes_copied =  bytes_to_copy;     /* the amount of bytes returned to the caller */
        remaining_bytes =  bytes_to_copy;   /* for use in the copy loop */
    }
    else
    {
        *bytes_copied =  buffer_length;
        remaining_bytes =  buffer_length;
    }

    /* Loop to copy bytes from packet(s).  */
    while (working_packet_ptr && remaining_bytes)
    {

        /* Calculate bytes to copy.  */
        bytes_to_copy = working_packet_ptr -> nx_packet_append_ptr - source_ptr;
        if(remaining_bytes < bytes_to_copy)
            bytes_to_copy = remaining_bytes;

        /* Copy data from this packet.  */        
        memcpy(destination_ptr, source_ptr, bytes_to_copy); /* Use case of memcpy is verified. */

        /* Update the pointers. */
        destination_ptr += bytes_to_copy;
        remaining_bytes -= bytes_to_copy;

        /* Move to next packet.  */
        working_packet_ptr =  working_packet_ptr -> nx_packet_next;

        /* Check for a next packet.  */
        if (working_packet_ptr)
        {

            /* Setup new source pointer.  */
            source_ptr = working_packet_ptr -> nx_packet_prepend_ptr;
        }
    }

    /* Return successful completion.  */
    return(NX_SUCCESS);

}
#endif /* NX_BSD_INCLUDE_DATA_EXTRACT_OFFSET */

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_timer_entry                                  PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function is called when the nx_bsd_socket_wait_timer expires.  */
/*    It signals the BSD thread task to check and decrement the time      */
/*    remaining on all sockets suspended in the wait state.               */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    info                                 Timer thread data (not used)   */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    tx_event_flags_set                   Sets the WAIT event in the BSD */
/*                                              event group               */ 
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    ThreadX                                                             */ 
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
#ifdef NX_BSD_TIMEOUT_PROCESS_IN_TIMER
VOID  nx_bsd_timer_entry(ULONG info)
{
    nx_bsd_timeout_process();
}
#endif


/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_socket_set_inherited_settings                PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function applies the socket options of the specified parent    */
/*    (master) socket to the specified child (secondary) socket, if BSD   */
/*    extended socket options are enabled. If they are not, this function */
/*    has no effect.                                                      */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    master_sock_id                       Source of socket options       */ 
/*    secondary_sock_id                    Socket inheriting options      */
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    NX_SUCCESS                          Successful completion           */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    ThreadX                                                             */ 
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
UINT nx_bsd_socket_set_inherited_settings(UINT master_sock_id, UINT secondary_sock_id)
{

    /* Update the secondary socket options from the master socket. */
    if(nx_bsd_socket_array[master_sock_id].nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING)
        nx_bsd_socket_array[secondary_sock_id].nx_bsd_socket_option_flags |= NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING;
    else
        nx_bsd_socket_array[secondary_sock_id].nx_bsd_socket_option_flags &= (ULONG)(~NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING);

    if(nx_bsd_socket_array[master_sock_id].nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_REUSEADDR)
        nx_bsd_socket_array[secondary_sock_id].nx_bsd_socket_option_flags |= NX_BSD_SOCKET_ENABLE_OPTION_REUSEADDR;
    else
        nx_bsd_socket_array[secondary_sock_id].nx_bsd_socket_option_flags &= (ULONG)(~NX_BSD_SOCKET_ENABLE_OPTION_REUSEADDR);

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
    nx_bsd_socket_array[secondary_sock_id].nx_bsd_socket_tcp_socket -> nx_tcp_socket_rx_window_maximum =
                                                         nx_bsd_socket_array[master_sock_id].nx_bsd_socket_tcp_socket -> nx_tcp_socket_rx_window_maximum;
#endif


    /* Does this version of NetX support TCP keep alive? */
    /* Is NetX currently enabled for TCP keep alive? */
#ifdef NX_ENABLE_TCP_KEEPALIVE

    nx_bsd_socket_array[secondary_sock_id].nx_bsd_socket_tcp_socket -> nx_tcp_socket_keepalive_enabled = 
                        nx_bsd_socket_array[master_sock_id].nx_bsd_socket_tcp_socket -> nx_tcp_socket_keepalive_enabled;

#endif /* NX_ENABLE_TCP_KEEPALIVE */


    return NX_SUCCESS;
}


/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_isspace                                      PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function determines if the input character is white space      */
/*    (ascii characters 0x09 - 0x0D or space (0x20).                      */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    c                                    Input character to examine     */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    NX_TRUE                              Input character is white space */ 
/*    NX_FALSE                             Input character not white space*/ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    ThreadX                                                             */ 
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
static UINT nx_bsd_isspace(UCHAR c)
{

    /* Check for horizontal, vertical tabs, carriage return or formfeed characters. */
    if ((c >= 0x09) && (c <= 0x0D))
    {
        return NX_TRUE;
    }
    /* Check for a single space character*/
    else if (c == 20)
    {
        return NX_TRUE;
    }
    else 
        /* Not a white space character. */
        return NX_FALSE;
}


/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_islower                                      PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function determines if the input character is lower case       */
/*    alphabetic character.                                               */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    c                                    Input character to examine     */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    NX_TRUE                              Input character is lower case  */ 
/*    NX_FALSE                             Input character not lower case */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    ThreadX                                                             */ 
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
static UINT nx_bsd_islower(UCHAR c)
{

    /* Check if characters is any character 'a' through 'z'. */
    if ((c >= 0x61) && (c <= 0x7A))
    {

        return NX_TRUE;
    }
    else 
        return NX_FALSE;

}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_isdigit                                      PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function determines if the input character is a digit (0-9)    */
/*    Does not include hex digits, (see nx_bsd_isxdigit).                 */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    c                                    Input character to examine     */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    NX_TRUE                              Input character is a digit     */ 
/*    NX_FALSE                             Input character not a digit    */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    ThreadX                                                             */ 
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
static UINT nx_bsd_isdigit(UCHAR c)
{

    /* Is the character any digit between 0 and 9? */
    if ((c >= 0x30) && (c <= 0x39))
    {
        return NX_TRUE;
    }
    else 
        return NX_FALSE;
}


/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_isxdigit                                     PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function determines if the input character is a digit (0-9)    */
/*    or hex digit (A - F, or a-f).  For decimal digits, see              */
/*    nx_bsd_isdigit.                                                     */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    c                                    Input character to examine     */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    NX_TRUE                              Input character is hex digit   */ 
/*    NX_FALSE                             Input character not hex digit  */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    ThreadX                                                             */ 
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
static UINT nx_bsd_isxdigit(UCHAR c)
{

    /* Is the character any digit between 0 - 9? */
    if ((c >= 0x30) && (c <= 0x39))
    {
        return NX_TRUE;
    }

    /* Or is the character any base 16 digit A-F? */
    if ((c >= 0x41) && (c <= 0x46))
    {
        return NX_TRUE;
    }

    /* Lastly, check if character is any base 16 digit a-f? */
    if ((c >= 0x61) && (c <= 0x66))
    {
        return NX_TRUE;
    }
    else 
        return NX_FALSE;
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    set_errno                                           PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function sets the error on the current socket (thread) for     */
/*    sockets enabled with BSD extended socket options. For sockets not   */
/*    enabled with extended features, this function has no effect.        */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    tx_errno                                Socket error status code    */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    ThreadX                                                             */ 
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
VOID set_errno(INT tx_errno)
{

TX_INTERRUPT_SAVE_AREA
TX_THREAD       *current_thread_ptr;


      TX_DISABLE

      current_thread_ptr =  tx_thread_identify();
      current_thread_ptr -> bsd_errno = tx_errno; 
      
      TX_RESTORE  

      return;
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    get_errno                                           PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function retrieves the error on the current socket (thread) for*/
/*    sockets enabled with BSD extended socket options. For sockets not   */
/*    enabled with extended features, this function has no effect.        */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    Socket error status code                                            */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    ThreadX                                                             */ 
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
INT _nx_get_errno()
{

TX_INTERRUPT_SAVE_AREA
INT val;
TX_THREAD       *current_thread_ptr;


    TX_DISABLE

    current_thread_ptr =  tx_thread_identify();
    val = current_thread_ptr -> bsd_errno;
    
    TX_RESTORE  
    
    return (val);
}

      
/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_select_wakeup                                PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function checks the suspend list for a given socket being      */ 
/*    readable or writeable.                                              */ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    sock_id                               BSD socket ID                 */
/*    fd_sets                               The FD set to check           */  
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    FD_ZERO                               Zeros out an FD Set           */
/*    FD_SET                                Set a socket in the FDSET     */
/*    TX_DISABLE                            Disable Interrupt             */
/*    TX_RESTORE                            Enable Interrupt              */
/*    tx_event_flags_set                    Set an event flag             */
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    nx_bsd_timeout_process                                              */ 
/*    nx_bsd_tcp_receive_notify                                           */ 
/*    nx_bsd_tcp_establish_notify                                         */ 
/*    nx_bsd_tcp_socket_disconnect_notify                                 */ 
/*    nx_bsd_udp_packet_received                                          */ 
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
static VOID nx_bsd_select_wakeup(UINT sock_id, UINT fd_sets)
{
TX_INTERRUPT_SAVE_AREA
fd_set                  local_fd;
TX_THREAD               *suspended_thread;
ULONG                   suspended_count;
ULONG                   original_suspended_count;
NX_BSD_SOCKET_SUSPEND   *suspend_info;


    /* At this point the thread should NOT own the IP mutex, and it must own the 
       BSD mutex. */

 
    FD_ZERO(&local_fd);
    FD_SET((INT)sock_id + NX_BSD_SOCKFD_START, &local_fd);

    /* Disable interrupts temporarily.  */
    TX_DISABLE

    /* Setup the head pointer and the count.  */
    suspended_thread =   nx_bsd_events.tx_event_flags_group_suspension_list;
    suspended_count =    nx_bsd_events.tx_event_flags_group_suspended_count;

    /* Save the original suspended count.  */
    original_suspended_count =  suspended_count;

    /* Loop to examine all threads suspended on select via the BSD event flag group.  */
    while (suspended_count--)
    {

        /* Determine if this thread is suspended on select.  */
        if (suspended_thread -> tx_thread_suspend_info == NX_BSD_SELECT_EVENT)
        {
        
            /* Yes, this thread is suspended on select.  */

            /* Pickup a pointer to its select suspend structure.  */
            suspend_info =  (NX_BSD_SOCKET_SUSPEND *) suspended_thread -> tx_thread_additional_suspend_info;

            /* Now determine if this thread was waiting for this socket.  */
            if ((fd_sets & FDSET_READ) && (FD_ISSET((INT)sock_id + NX_BSD_SOCKFD_START, &suspend_info -> nx_bsd_socket_suspend_read_fd_set)))
            {

                /* Copy the local fd over so that the return shows the receive socket.  */
                suspend_info -> nx_bsd_socket_suspend_read_fd_set = local_fd;
                
                /* Adjust the suspension type so that the event flag set below will wakeup the thread 
                   selecting.  */
                suspended_thread -> tx_thread_suspend_info =  NX_BSD_RECEIVE_EVENT;
            }        

            /* Now determine if this thread was waiting for this socket.  */
            if ((fd_sets & FDSET_WRITE) && (FD_ISSET((INT)sock_id + NX_BSD_SOCKFD_START, &suspend_info -> nx_bsd_socket_suspend_write_fd_set)))
            {

                /* Copy the local fd over so that the return shows the receive socket.  */
                suspend_info -> nx_bsd_socket_suspend_write_fd_set = local_fd;
                
                /* Adjust the suspension type so that the event flag set below will wakeup the thread 
                   selecting.  */
                suspended_thread -> tx_thread_suspend_info =  NX_BSD_RECEIVE_EVENT;
            }        

            /* Now determine if this thread was waiting for this socket.  */
            if ((fd_sets & FDSET_EXCEPTION) && (FD_ISSET((INT)sock_id + NX_BSD_SOCKFD_START, &suspend_info -> nx_bsd_socket_suspend_exception_fd_set)))
            {

                /* Copy the local fd over so that the return shows the receive socket.  */
                suspend_info -> nx_bsd_socket_suspend_exception_fd_set = local_fd;
                
                /* Adjust the suspension type so that the event flag set below will wakeup the thread 
                   selecting.  */
                suspended_thread -> tx_thread_suspend_info =  NX_BSD_RECEIVE_EVENT;
            }        

            /* Clear FD that is not set. */
            if (suspended_thread -> tx_thread_suspend_info == NX_BSD_RECEIVE_EVENT)
            {
                if (!(fd_sets & FDSET_READ) && (FD_ISSET((INT)sock_id + NX_BSD_SOCKFD_START, &suspend_info -> nx_bsd_socket_suspend_read_fd_set)))
                {

                    /* Clear read FD. */
                    FD_CLR((INT)sock_id + NX_BSD_SOCKFD_START, &suspend_info -> nx_bsd_socket_suspend_read_fd_set);
                }

                if (!(fd_sets & FDSET_WRITE) && (FD_ISSET((INT)sock_id + NX_BSD_SOCKFD_START, &suspend_info -> nx_bsd_socket_suspend_write_fd_set)))
                {

                    /* Clear write FD. */
                    FD_CLR((INT)sock_id + NX_BSD_SOCKFD_START, &suspend_info -> nx_bsd_socket_suspend_write_fd_set);
                }

                if (!(fd_sets & FDSET_EXCEPTION) && (FD_ISSET((INT)sock_id + NX_BSD_SOCKFD_START, &suspend_info -> nx_bsd_socket_suspend_exception_fd_set)))
                {

                    /* Clear exception FD. */
                    FD_CLR((INT)sock_id + NX_BSD_SOCKFD_START, &suspend_info -> nx_bsd_socket_suspend_exception_fd_set);
                }
            }
        }

        /* Now move to the next event.  */
        suspended_thread =  suspended_thread -> tx_thread_suspended_next;
        
        /* Restore interrupts.  */
        TX_RESTORE
            
        /* Disable interrupts again.  */
        TX_DISABLE

        /* Determine if something changes on the suspension list... this could have happened if there 
           was a timeout or a wait abort on the thread.  */
        if (original_suspended_count != nx_bsd_events.tx_event_flags_group_suspended_count)
        {
        
            /* Something changed, so simply restart the search.  */
            
            /* Setup the head pointer and the count.  */
            suspended_thread =   nx_bsd_events.tx_event_flags_group_suspension_list;
            suspended_count =    nx_bsd_events.tx_event_flags_group_suspended_count;

            /* Save the original suspended count.  */
            original_suspended_count =  suspended_count;
        } 
    }

    /* Restore interrupts.  */
    TX_RESTORE
    
    /* Wakeup all threads that are attempting to perform a receive or that had their select satisfied.  */
    tx_event_flags_set(&nx_bsd_events, NX_BSD_RECEIVE_EVENT, TX_OR);

    return;

}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_set_error_code                               PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This is sets the BSD error code based on NetX API return code       */ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    bsd_socket_ptr                        Pointer to the BSD socket     */
/*    status_code                           NetX API return code          */  
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    set_errno                             Sets the BSD errno            */
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    connect                                                             */ 
/*    bind                                                                */ 
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
static VOID nx_bsd_set_error_code(NX_BSD_SOCKET *bsd_socket_ptr, UINT status_code)
{
    switch(status_code)
    {
        case NX_NOT_CLOSED:
            /* TCP connection is not closed state. */
            set_errno(EISCONN);
            break;

        case NX_PTR_ERROR:
        case NX_INVALID_PORT:
            /* Invalid arguement. */
            set_errno(EINVAL);
            break;

        case NX_MAX_LISTEN:
            set_errno(ENOBUFS);  
            break;

        case NX_PORT_UNAVAILABLE:
        case NX_NO_FREE_PORTS:
            set_errno(EADDRNOTAVAIL);
            break;

        case NX_ALREADY_BOUND:
            set_errno(EINVAL);
            break;

        case NX_WAIT_ABORTED:
            set_errno(ETIMEDOUT);
            break;

        case NX_NOT_CONNECTED:
            /* NX TCP connect service may return NX_NOT_CONNECTED if the timeout is WAIT_FOREVER. */
            set_errno(ECONNREFUSED);
            break;

        case NX_IN_PROGRESS:
            /* The NetX "in progress" status is the equivalent of the non blocking BSD socket waiting 
               to connect. This can only happen if timeout is NX_NO_WAIT.*/
            if (bsd_socket_ptr -> nx_bsd_socket_option_flags & NX_BSD_SOCKET_ENABLE_OPTION_NON_BLOCKING)
            {
                bsd_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTION_INPROGRESS;
                set_errno(EINPROGRESS);
            }
            else
                set_errno(EINTR);
            break;

        case NX_INVALID_INTERFACE:
        case NX_IP_ADDRESS_ERROR:
            set_errno(ENETUNREACH);
            break;

        case NX_NOT_ENABLED:
            set_errno(EPROTONOSUPPORT);
            break;

        case NX_NOT_BOUND:
        case NX_DUPLICATE_LISTEN:
        default:
            set_errno(EINVAL);
            break;
    }

    return;
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_udp_packet_received                          PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This is executed as part of the UDP packet receive callback         */ 
/*    function.                                                           */
/*                                                                        */ 
/*    This routine puts an incoming UDP packet into the appropriate       */ 
/*    UDP BSD socket, taking into consideration that multiple BSD sockets */ 
/*    may be mapped to the same NetX UDP socket.                          */ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    sockID                                The BSD socket descriptor     */
/*    packet_ptr                            The incoming UDP packet       */  
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    nx_packet_release                     Release a packet that is not  */
/*                                            received by any sockets.    */
/*    nx_bsd_select_wakeup                  Wake up any asychronous       */ 
/*                                            receive call                */ 
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    nx_bsd_udp_receive_notify                                           */ 
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
static VOID nx_bsd_udp_packet_received(INT sockID, NX_PACKET *packet_ptr)
{

NX_BSD_SOCKET *bsd_ptr;
ULONG          addr_family;
NX_BSD_SOCKET *exact_match = NX_NULL;
NX_BSD_SOCKET *receiver_match = NX_NULL;  
NX_BSD_SOCKET *wildcard_match = NX_NULL; 
NX_INTERFACE   *interface_ptr;


    bsd_ptr = &nx_bsd_socket_array[sockID];
    
    addr_family = AF_INET;
    interface_ptr = packet_ptr -> nx_packet_ip_interface;

    /* Start the search for the BSD socket we received this packet on from current input socket ID.  */
    bsd_ptr = &nx_bsd_socket_array[sockID];

    do
    {
        /* Skip the sockets with different address family. */
        if(bsd_ptr -> nx_bsd_socket_family == addr_family)
        {
            /* bsd_ptr points to a related UDP socket. */
            if(bsd_ptr -> nx_bsd_socket_local_bind_interface == NX_BSD_LOCAL_IF_INADDR_ANY)
            {
                wildcard_match = bsd_ptr;
            }
            else if(((ULONG)(interface_ptr) == bsd_ptr -> nx_bsd_socket_local_bind_interface)) 
            {

                receiver_match = bsd_ptr;
            }
            else 
            {

                /* Does not match the local interface. Move to the next entry. */
                bsd_ptr = bsd_ptr -> nx_bsd_socket_next;
                continue;
            }

            /* At this point this socket is either a wildcard match or a receiver match. */

            /* If the socket is connected, we check for sender's address match. */
            if(bsd_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED)
            {

                nx_udp_source_extract(packet_ptr,
                                      &bsd_ptr -> nx_bsd_socket_source_ip_address,
                                      (UINT *)&bsd_ptr -> nx_bsd_socket_source_port);

                if(bsd_ptr -> nx_bsd_socket_family == AF_INET)
                {

                    /* Now we can check for an exact match based on sender IP address and port. */
                    if((bsd_ptr -> nx_bsd_socket_source_ip_address == 
                        bsd_ptr -> nx_bsd_socket_peer_ip) &&
                       (bsd_ptr -> nx_bsd_socket_source_port ==
                        bsd_ptr -> nx_bsd_socket_peer_port))
                    {
                        exact_match = bsd_ptr;
                    }
                }
            
                if(exact_match != NX_NULL)
                    break;
                
                if(receiver_match != NX_NULL)
                    receiver_match = NX_NULL;
                
                if(wildcard_match != NX_NULL)
                    wildcard_match = NX_NULL;
            }
        } 
        
        /* Move to the next entry. */
        bsd_ptr = bsd_ptr -> nx_bsd_socket_next;

    }while(bsd_ptr != &nx_bsd_socket_array[sockID]);
   
    /* Let bsd_ptr point to the matched socket. */
    if(exact_match != NX_NULL)
        bsd_ptr = exact_match;
    else if(receiver_match != NX_NULL)
        bsd_ptr = receiver_match;
    else if(wildcard_match != NX_NULL)
        bsd_ptr = wildcard_match;
    else
    {
        /* This packet is not for any of the BSD sockets. Release the packet and we are done. */
        nx_packet_release(packet_ptr);
        
        return;
    }
    
    /* Move the packet to the socket internal receive queue. */
    
    if(bsd_ptr -> nx_bsd_socket_received_byte_count_max &&
       (bsd_ptr -> nx_bsd_socket_received_byte_count >= bsd_ptr -> nx_bsd_socket_received_byte_count_max))
    {

        /* Receive buffer is full.  Release the packet and return. */
        nx_packet_release(packet_ptr);
        
        return;
    }

    /* Drop the packet if the receive queue exceeds max depth.*/
    if(bsd_ptr -> nx_bsd_socket_received_packet_count >=
       bsd_ptr -> nx_bsd_socket_received_packet_count_max)
    {

        /* Receive buffer is full.  Release the packet and return. */
        nx_packet_release(packet_ptr);
        
        return;
    }
    if(bsd_ptr -> nx_bsd_socket_received_packet)
    {
        bsd_ptr -> nx_bsd_socket_received_packet_tail -> nx_packet_queue_next = packet_ptr;
    }
    else
    {

        bsd_ptr -> nx_bsd_socket_received_packet = packet_ptr;
        bsd_ptr -> nx_bsd_socket_received_packet_offset = 0;
    }

    bsd_ptr -> nx_bsd_socket_received_packet_tail = packet_ptr;
    bsd_ptr -> nx_bsd_socket_received_byte_count += packet_ptr -> nx_packet_length;
    bsd_ptr -> nx_bsd_socket_received_packet_count++;
        
    nx_bsd_select_wakeup((UINT)(bsd_ptr -> nx_bsd_socket_id), FDSET_READ);

    return;
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_tcp_syn_received_notify                      PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function checks if the socket has a connection request.        */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    socket_ptr                           Socket receiving the packet    */
/*    packet_ptr                           Pointer to the received packet */  
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    0                                     Not a valid match             */
/*    1                                     Valid match found             */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX                                                                */ 
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
static UINT  nx_bsd_tcp_syn_received_notify(NX_TCP_SOCKET *socket_ptr, NX_PACKET *packet_ptr)
{

UINT            bsd_socket_index;    
INT             i;
INT             sockID_find;
ULONG           addr_family;
INT             search_index;
INT             receiver_match = NX_BSD_MAX_SOCKETS;
INT             wildcard_match = NX_BSD_MAX_SOCKETS;
NX_BSD_SOCKET  *bsd_socket_ptr;
NX_INTERFACE   *interface_ptr;


    bsd_socket_index = (UINT)socket_ptr -> nx_tcp_socket_reserved_ptr;
    
    if(bsd_socket_index >= NX_BSD_MAX_SOCKETS)
    {

        /* Bad socket index... simply return!  */
        return(NX_FALSE);
    }

    nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTION_INPROGRESS;

    addr_family = AF_INET;

    /* Start the search at the position of the input socket. */
    search_index = (INT)bsd_socket_index;

    /* Get the packet interface. */
    interface_ptr = packet_ptr -> nx_packet_ip_interface;

    for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
    {

        bsd_socket_ptr = &nx_bsd_socket_array[search_index];
        
        /* Skip the unrelated sockets. */
        if((bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_TCP) &&
           (bsd_socket_ptr -> nx_bsd_socket_family == addr_family) &&
           ((bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CONNECTED) == 0) &&
           (bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_MASTER_SOCKET) &&
           (bsd_socket_ptr -> nx_bsd_socket_local_port == socket_ptr -> nx_tcp_socket_port) &&  
           (bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE))
        {

            if(bsd_socket_ptr -> nx_bsd_socket_local_bind_interface == NX_BSD_LOCAL_IF_INADDR_ANY)
            {

                wildcard_match = search_index;
            }
            else if(((ULONG)(interface_ptr) == bsd_socket_ptr -> nx_bsd_socket_local_bind_interface))
            {

                receiver_match = search_index;

                /* Found a receiver match, which is a tighter match than the wildcard match.
                   So we can get out of the loop. */
                break;
            }
        }

        /*  Move to the next entry. */
        search_index++;
        
        if(search_index >= NX_BSD_MAX_SOCKETS)
            search_index = 0;
    }

    if(receiver_match != NX_BSD_MAX_SOCKETS)
        sockID_find = receiver_match;
    else if(wildcard_match != NX_BSD_MAX_SOCKETS)
        sockID_find = wildcard_match;
    else
    {

        /* No match found.  Simply return .*/
        return(NX_FALSE);
    }

    /*  Found the listening master socket.  Update the master socket ID of the input socket. */
    nx_bsd_socket_array[bsd_socket_index].nx_bsd_socket_union_id.nx_bsd_socket_master_socket_id = sockID_find;

    return(NX_TRUE);
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_tcp_create_listen_socket                     PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This routine sets up the input socket as a listen socket.           */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    master_sockid                        Index to the master socket     */
/*    backlog                              Size of the socket listen queue*/  
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    NX_SOC_OK                             Successfully set up socket    */
/*    NX_SOC_ERROR                          Error setting up the socket   */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    socket                                Allocate a BSD socket         */
/*    nx_bsd_socket_set_inherited_settings  Apply master socket options   */
/*    nx_tcp_server_socket_listen           Enable the socket to listen   **/
/*    nx_tcp_server_socket_accept           Wait for connection request   */
/*    nx_tcp_server_socket_relisten         Reset the socket to listen    */
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX                                                                */ 
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
static INT nx_bsd_tcp_create_listen_socket(INT master_sockid, INT backlog)
{

INT                 i;
UINT                status;
UINT                local_port;
NX_BSD_SOCKET       *master_socket_ptr = &nx_bsd_socket_array[master_sockid];
NX_BSD_SOCKET       *bsd_secondary_socket;
NX_BSD_SOCKET       *bsd_socket_ptr;
NX_TCP_SOCKET       *sec_socket_ptr;
INT                 secondary_sockID = NX_BSD_MAX_SOCKETS;


    /* This is called from BSD internal code so the BSD mutex is obtained. */
 
    /* Search through the sockets to find a master socket that is listening on the same port. */
    for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
    {

        /* Skip the entry if it is not master socket */
        if((nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_MASTER_SOCKET) == 0)
            continue;

        /* Skip the current master socket. */
        if(i == master_sockid)
            continue;

        /* Skip the entry if it is not TCP */
        if(nx_bsd_socket_array[i].nx_bsd_socket_protocol != NX_PROTOCOL_TCP)
            continue;

        /* Skip the entry if the the secondary socket id field is not valid. */
        if(nx_bsd_socket_array[i].nx_bsd_socket_union_id.nx_bsd_socket_secondary_socket_id == NX_BSD_MAX_SOCKETS)
            continue;

        /* Check if another master socket is listening on the same port.  */
        if((nx_bsd_socket_array[i].nx_bsd_socket_local_port == master_socket_ptr -> nx_bsd_socket_local_port) &&
           (nx_bsd_socket_array[i].nx_bsd_socket_union_id.nx_bsd_socket_secondary_socket_id 
            != (master_socket_ptr -> nx_bsd_socket_union_id.nx_bsd_socket_secondary_socket_id)) &&
           (nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_ENABLE_LISTEN))
        {

            /* This one is. Point to the same secondary socket. */
            (master_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id = 
              nx_bsd_socket_array[i].nx_bsd_socket_union_id.nx_bsd_socket_secondary_socket_id;
            master_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_ENABLE_LISTEN;
            master_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_SERVER_SECONDARY_SOCKET);
            master_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_client_type =  NX_FALSE;
            master_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_SERVER_MASTER_SOCKET;
            
            return(NX_SOC_OK);
        }
    }

    /* Did not find an existing master socket for listening. */

    /* Check for a valid backlog. */
    if(backlog)
    {

        /* Check backlog argument is within limits.  */
        if (backlog > NX_BSD_MAX_LISTEN_BACKLOG)
        {

            /* Error, invalid backlog.  */
            /* Set the socket error if extended socket options enabled. */
            set_errno(ENOBUFS);  

            /* Return error code.  */
            NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
            return(NX_SOC_ERROR);
        }
    }

    /* Now create a dedicated secondary socket to listen for next client connection.  */
    secondary_sockID =  socket((INT)(master_socket_ptr -> nx_bsd_socket_family), SOCK_STREAM, IPPROTO_TCP);

    /* Determine if there was an error.  */
    if (secondary_sockID == NX_SOC_ERROR)
    {

        /* Secondary socket create failed. Note: The socket thread error is set in socket().  */
        set_errno(ENOMEM);
        
        /* Return error code.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Adjust the secondary socket ID.  */
    secondary_sockID =  secondary_sockID - NX_BSD_SOCKFD_START;

    /* The master server socket will never connect to a client! For each successful 
       client connection there will be a new secondary server socket and 
       each such socket is associated with this master server socket. This is 
       the difference between NetX and BSD sockets. The NetX listen() service is used 
       with this secondary server socket.  */

    /* Set a pointer to the secondary socket. */
    bsd_secondary_socket = &nx_bsd_socket_array[secondary_sockID];

    /* Apply the master socket options to the secondary socket. */
    nx_bsd_socket_set_inherited_settings((UINT)master_sockid, (UINT)secondary_sockID);

    local_port = master_socket_ptr -> nx_bsd_socket_local_port;

    /* Invalidate the secondary master socket ID. */
    (bsd_secondary_socket -> nx_bsd_socket_union_id).nx_bsd_socket_master_socket_id = NX_BSD_MAX_SOCKETS;

    /* Now call listen for the secondary server socket.  */
    if(backlog)
        status = nx_tcp_server_socket_listen(nx_bsd_default_ip, local_port, bsd_secondary_socket -> nx_bsd_socket_tcp_socket, (UINT)backlog, NX_NULL);
    else
    {

        /* Since a zero backlog is specified, this secondary socket needs to share with another master socket. */
        bsd_secondary_socket -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_port = local_port;
        
        /* Check if a listen request is queued up for this socket. */
        nx_bsd_tcp_pending_connection(local_port, bsd_secondary_socket -> nx_bsd_socket_tcp_socket);

        status =  nx_tcp_server_socket_relisten(nx_bsd_default_ip, local_port, bsd_secondary_socket -> nx_bsd_socket_tcp_socket);
    }

    /* Check for an error.  */
    if ((status != NX_SUCCESS) && (status != NX_CONNECTION_PENDING))
    {

        /* Error, listen or relisten failed.  */

        /* Set the socket error depending on the NetX error status returned.  */
        nx_bsd_set_error_code(master_socket_ptr, status);

        /* Return error code.  */
        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);
    }

    /* Now mark this as a master server socket listening to client connections.  */
    master_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_ENABLE_LISTEN;
    master_socket_ptr -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_SERVER_SECONDARY_SOCKET);
    master_socket_ptr -> nx_bsd_socket_tcp_socket -> nx_tcp_socket_client_type =  NX_FALSE;
    master_socket_ptr -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_SERVER_MASTER_SOCKET;

    /* This is a master socket.  So we use the nx_bsd_socket_master_socket_id field to 
       record the secondary socket that is doing the real listen/accept work. */
    (master_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id = secondary_sockID;

    /* Mark the secondary server socket as assigned to this master server socket.   */
    bsd_secondary_socket -> nx_bsd_socket_status_flags &= (ULONG)(~NX_BSD_SOCKET_ACCEPTING);
    bsd_secondary_socket -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_SERVER_SECONDARY_SOCKET;
    bsd_secondary_socket -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_ENABLE_LISTEN;
    bsd_secondary_socket -> nx_bsd_socket_local_port              =  (USHORT)local_port;

    /* If the master server socket is marked as non-blocking, we need to 
       start the NetX accept process here. */

    sec_socket_ptr = bsd_secondary_socket -> nx_bsd_socket_tcp_socket;

    /* Allow accept from remote. */
    nx_tcp_server_socket_accept(sec_socket_ptr, 0);
   
    /* Set the master socket of other BSD TCP sockets that bind to the same port to the same secondary socket. */
    for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
    {

        bsd_socket_ptr = &nx_bsd_socket_array[i];

        if((bsd_socket_ptr -> nx_bsd_socket_protocol == NX_PROTOCOL_TCP) &&
           (!(bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_CLIENT)) &&
           (bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_SERVER_MASTER_SOCKET) &&
           (bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_ENABLE_LISTEN) &&
           (bsd_socket_ptr -> nx_bsd_socket_status_flags & NX_BSD_SOCKET_BOUND) &&
           (bsd_socket_ptr -> nx_bsd_socket_local_port == local_port))
        {
        
            (bsd_socket_ptr -> nx_bsd_socket_union_id).nx_bsd_socket_secondary_socket_id = secondary_sockID;
        }
    }        

    /* Check the relisten/listen status. */
    if(status == NX_CONNECTION_PENDING)
    {

        /* Set the connection pending flag. */
        bsd_secondary_socket -> nx_bsd_socket_status_flags |= NX_BSD_SOCKET_CONNECTION_INPROGRESS;

    }

    return(NX_SOC_OK);
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    nx_bsd_tcp_pending_connection                       PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This routine checks if the BSD TCP socket has a listen request      */
/*    queued up on in the specified port.                                 */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    local_port                           Listening port                 */
/*    socket_ptr                           Socket to check                */  
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    nx_bsd_tcp_syn_received_notify        Match connection request      */
/*                                             (packet) to input socket   */
/*    nx_packet_receive                     Release packet to packet pool */
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX                                                                */ 
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
static VOID nx_bsd_tcp_pending_connection(UINT local_port, NX_TCP_SOCKET *socket_ptr)
{

struct NX_TCP_LISTEN_STRUCT *listen_ptr;
NX_PACKET                   *packet_ptr;
NX_TCP_HEADER               *tcp_header_ptr;
UINT                         ret;


    listen_ptr = nx_bsd_default_ip -> nx_ip_tcp_active_listen_requests;

    if(listen_ptr)
    {

        do 
        {

            if((listen_ptr -> nx_tcp_listen_port == local_port) &&
               (listen_ptr -> nx_tcp_listen_queue_current))
            {

                do
                {

                    packet_ptr = listen_ptr -> nx_tcp_listen_queue_head;
                    
                    tcp_header_ptr = (NX_TCP_HEADER*)packet_ptr -> nx_packet_prepend_ptr;

                    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT)
                    {

                        ret = nx_bsd_tcp_syn_received_notify(socket_ptr, packet_ptr);

                        /* Yes. We are done. */
                        if(ret == NX_TRUE)
                        {

                            return;
                        }

                        listen_ptr -> nx_tcp_listen_queue_head = packet_ptr -> nx_packet_queue_next;
                        
                        if(packet_ptr == listen_ptr -> nx_tcp_listen_queue_tail)
                        {
                            listen_ptr -> nx_tcp_listen_queue_tail = NX_NULL;
                        }

                        listen_ptr -> nx_tcp_listen_queue_current--;

                        nx_packet_release(packet_ptr);
                        
                    }
                } while(listen_ptr -> nx_tcp_listen_queue_head);
            }

            listen_ptr = listen_ptr -> nx_tcp_listen_next;

        }while(listen_ptr != nx_bsd_default_ip -> nx_ip_tcp_active_listen_requests);
    }
}




#ifdef NX_BSD_RAW_SUPPORT

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_bsd_hardware_internal_sendto                    PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends raw packet to driver directly.                  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    bsd_socket_ptr                        Pointer to bsd socket         */
/*    msg                                   Message to send               */
/*    msgLength                             Length of message             */
/*    flags                                 Flags                         */
/*    destAddr                              Pointer to destination address*/
/*    destAddrLen                           Length of destination address */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    msgLength                             On success                    */
/*    NX_SOC_ERROR (-1)                     On failure                    */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nx_packet_data_append                 Append data to the packet     */
/*    nx_packet_release                     Release the packet on error   */
/*    tx_mutex_get                          Obtain exclusive access to    */
/*    tx_mutex_put                          Release exclusive access      */
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
static INT _nx_bsd_hardware_internal_sendto(NX_BSD_SOCKET *bsd_socket_ptr, CHAR *msg, INT msgLength, INT flags,  struct sockaddr* destAddr, INT destAddrLen)
{
UINT                if_index;
struct sockaddr_ll *destAddr_ll;    
UINT                status;
NX_PACKET          *packet_ptr = NX_NULL;

    NX_PARAMETER_NOT_USED(bsd_socket_ptr);
    NX_PARAMETER_NOT_USED(flags);

    /* Validate the parameters. */
    if(destAddr == NX_NULL)
    {
        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);        
    }

    if(destAddr -> sa_family != AF_PACKET)
    {
        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);        
    }

    if(destAddrLen != sizeof(struct sockaddr_ll))
    {
        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);        
    }

    destAddr_ll = (struct sockaddr_ll*)destAddr;

    /* Validate the interface ID */
    if_index = (UINT)(destAddr_ll -> sll_ifindex);
    if(if_index >= NX_MAX_IP_INTERFACES)
    {
        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);        
    }

    if(nx_bsd_default_ip -> nx_ip_interface[if_index].nx_interface_valid == 0)
    {
        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);        
    }

    /* Validate the packet length */
    if(msgLength > (INT)(nx_bsd_default_ip -> nx_ip_interface[if_index].nx_interface_ip_mtu_size + 18))
    {    
        /* Set the socket error if extended socket options enabled. */
        set_errno(EINVAL);  

        NX_BSD_ERROR(NX_SOC_ERROR, __LINE__);
        return(NX_SOC_ERROR);        
    }

    status = nx_packet_allocate(nx_bsd_default_packet_pool, &packet_ptr, NX_PHYSICAL_HEADER, NX_NO_WAIT);

    /* Check for errors.   */
    if (status != NX_SUCCESS)
    {

        /* Set the socket error.  */
        set_errno(ENOBUFS);

        /* Return an error status.*/
        NX_BSD_ERROR(status, __LINE__);
        return(NX_SOC_ERROR);
    }    

    /* Set IP interface. */
    packet_ptr -> nx_packet_ip_interface = &nx_bsd_default_ip -> nx_ip_interface[if_index];

    /* Now copy the data into the NetX packet.  */
    status =  nx_packet_data_append(packet_ptr, (VOID *) msg, (ULONG)msgLength, nx_bsd_default_packet_pool, NX_NO_WAIT);

    /* Was the data copy successful?  */
    if (status != NX_SUCCESS)
    {

        nx_packet_release(packet_ptr);

        /* Set the socket error.  */
        set_errno(ENOBUFS);

        /* Return an error status.*/
        NX_BSD_ERROR(status, __LINE__);
        return(NX_SOC_ERROR);
    }


    /* Obtain the BSD lock. */
    status = tx_mutex_get(nx_bsd_protection_ptr, NX_BSD_TIMEOUT);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        nx_packet_release(packet_ptr);
        
        /* Set the socket error if extended socket options enabled. */
        set_errno(EACCES);  

        /* Return an error. */
        NX_BSD_ERROR(NX_BSD_MUTEX_ERROR, __LINE__);
        return(NX_SOC_ERROR); 
    }

    _nx_driver_hardware_packet_send(packet_ptr);

    /* Release the mutex. */
    tx_mutex_put(nx_bsd_protection_ptr);

    return(msgLength);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_bsd_hardware_packet_received                    PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function receives raw packet from driver directly.             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer to received packet    */
/*    consumed                              Return packet consumed or not */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_bsd_select_wakeup                  Wake up any asychronous       */ 
/*                                            receive call                */ 
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
static VOID  _nx_bsd_hardware_packet_received(NX_PACKET *packet_ptr, UCHAR *consumed)
{

UINT i;        
UINT sockid = NX_BSD_MAX_SOCKETS;
NX_BSD_SOCKET *bsd_ptr;

    /* Initialize the consumed to be false. */
    *consumed = NX_FALSE;

    /* Find the socket with the matching interface.  Put the packet into the socket's recevie queue. */
    for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
    {
        if((nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE) &&
                (nx_bsd_socket_array[i].nx_bsd_socket_family == AF_PACKET) &&
                ((nx_bsd_socket_array[i].nx_bsd_socket_local_bind_interface == NX_BSD_LOCAL_IF_INADDR_ANY) ||
                 (nx_bsd_socket_array[i].nx_bsd_socket_local_bind_interface == (ULONG)(packet_ptr -> nx_packet_ip_interface))))
        {
            sockid = i;
        }
    }
    if(sockid == NX_BSD_MAX_SOCKETS)
    {
        /* No BSD sockets are avaialble for this frame type. */
        return;
    }
    /* Now we need to put the packet into the socket. */
    bsd_ptr = &nx_bsd_socket_array[sockid];

    /* Drop the packet if the receive queue exceeds max depth. */
    if(bsd_ptr -> nx_bsd_socket_received_packet_count >=
            bsd_ptr -> nx_bsd_socket_received_packet_count_max)
    {
        return;
    }

#ifndef NX_DISABLE_BSD_RAW_PACKET_DUPLICATE
    /* Duplicate the packet. */
    if (nx_packet_copy(packet_ptr, &packet_ptr, nx_bsd_default_packet_pool, NX_NO_WAIT) != NX_SUCCESS)
    {
        return;
    }
#else
    /* Consume the packet. IP layer will not see it. */
    *consumed = NX_TRUE;
#endif /* NX_DISABLE_BSD_RAW_PACKET_DUPLICATE */

    if(bsd_ptr -> nx_bsd_socket_received_packet)
    {
        bsd_ptr -> nx_bsd_socket_received_packet_tail -> nx_packet_queue_next = packet_ptr;
    }
    else
    {
        bsd_ptr -> nx_bsd_socket_received_packet = packet_ptr;
        bsd_ptr -> nx_bsd_socket_received_packet_offset = 0;
    }

    bsd_ptr -> nx_bsd_socket_received_packet_tail = packet_ptr;
    bsd_ptr -> nx_bsd_socket_received_byte_count += packet_ptr -> nx_packet_length;
    bsd_ptr -> nx_bsd_socket_received_packet_count ++;

    nx_bsd_select_wakeup(sockid, FDSET_READ);

    return;
}
#endif /* NX_BSD_RAW_SUPPORT */



/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    inet_pton                                           PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function converts an IP address from  presentation to numeric. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    af                                    Either AF_INET or AF_INET6    */
/*    src                                   A pointer pointing to the     */
/*                                            presentation of IP address  */
/*    dst                                   A pointer pointing to the     */
/*                                            destination memory          */ 
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                1 OK                          */  
/*                                          0 invalid presentation        */
/*                                          -1 error                      */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    inet_aton                             Convert IPv4 address from     */
/*                                          presentation to numeric       */
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
INT  inet_pton(INT af, const CHAR *src, VOID *dst)
{

struct  in_addr ipv4_addr;

    if(af == AF_INET)
    {
        /* Convert IPv4 address from presentation to numeric. */
        if(inet_aton(src, &ipv4_addr))
        {
            /* Copy the IPv4 address to the destination. */
            *((ULONG *)dst) = ipv4_addr.s_addr;
            return 1;
        }
        return 0;
    }
    else
    {
        /* Error. */
        return -1;
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    inet_ntop                                           PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function converts an IP address from  numeric to presentation. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    af                                    Either AF_INET or AF_INET6    */
/*    src                                   A void pointer pointing to    */
/*                                           network byte order IP address*/
/*    dst                                   A char pointer pointing to    */
/*                                           the destination buffer       */
/*    size                                  The size of the destination   */
/*                                           buffer                       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    dst                                   The destination buffer        */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    inet_ntoa_internal                    Convert IPv4 address from     */
/*                                          numeric to presentation       */
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
const CHAR *inet_ntop(INT af, const VOID *src, CHAR *dst, socklen_t size)
{


    
    if(af == AF_INET)
    {
        /* Convert IPv4 address from numeric to presentation. */
        if(inet_ntoa_internal(src, dst, size))
            return dst;
        else
            return NX_NULL;
    }
    else 
    {
        return NX_NULL;
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    inet_ntoa_internal                                  PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function converts an IPv4 address to a string and returns the  */
/*    size of the string.                                                 */ 
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    src                                   A void pointer pointing to    */
/*                                            IPv4 address                */
/*    dst                                   A char pointer pointing to    */
/*                                            the destination buffer      */
/*    dst_size                              The size of the destination   */
/*                                            buffer                      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    index                                 The size of the IPv4 address  */
/*                                            string                      */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                                Set the memory to 0           */
/*    bsd_number_convert                    Convert a number to string    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX BSD Layer Source Code                                          */ 
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

static INT inet_ntoa_internal(const VOID *src, CHAR *dst, ULONG dst_size)
{
ULONG temp;
UINT size;
UINT index = 0;


    /* Set a local pointer to move up the buffer. */
    temp = ntohl(*((ULONG *)src));

    memset(dst, 0, dst_size);

    /* Convert the first number to a string. */
    size = bsd_number_convert((temp >> 24), &dst[0], dst_size - index, 10);
    
    if(!size)
        return 0;

    /* Move up the index and buffer pointer. */
    index += size;
        
    /* Check the rest of the dst buffer. */
    if((dst_size - index) < 1)
        return 0; 

    /* Add the decimal. */
    dst[index++] = '.';

    /* And repeat three more times...*/
    size = bsd_number_convert((temp >> 16) & 0xff, &dst[index], dst_size - index, 10);

    if(!size)
        return 0;

    index += size;

    if((dst_size - index) < 1)
        return 0; 

    dst[index++] = '.';

    size = bsd_number_convert((temp >> 8) & 0xff, &dst[index], dst_size - index, 10);

    if(!size)
        return 0;

    index += size;

    if((dst_size - index) < 1)
        return 0; 

    dst[index++] = '.';

    size = bsd_number_convert(temp & 0xff, &dst[index], dst_size - index, 10);

    if(!size)
        return 0;

    index += size;

    if((dst_size - index) < 1)
        return 0; 

    dst[index++] = '\0';

    /* Return the size of the dst string. */
    return((INT)(index));
}


/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    getaddrinfo                                         PORTABLE C      */ 
/*                                                           6.1.12       */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function returns one or more addrinfo structures according to  */
/*    the specified node and service.                                     */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*   node                                   Node is either a hostname or  */
/*                                           an address string(dotted-    */
/*                                           decimal for IPv4).           */
/*   service                                Service is either a service   */
/*                                           name or a decimal port number*/ 
/*                                           string.                      */
/*   hints                                  Hints is either a null pointer*/ 
/*                                           or a pointer to an addrinfo  */ 
/*                                           structure that the caller    */
/*                                           fills in with hints about the*/ 
/*                                           types of information the     */
/*                                           caller wants returned.       */      
/*   res                                    Pointer to the returned       */
/*                                           addrinfo list.               */
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    status                                0 if OK, nonzero on errors    */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    bsd_string_to_number                  Convert a string to a number  */
/*    htons                                 Host byte order to network    */ 
/*                                          byte order                    */
/*    memcmp                                Memory compare                */
/*    inet_pton                             Convert IP address from       */ 
/*                                          presentation to numeric       */
/*    tx_block_allocate                     Allocate memory for address or*/ 
/*                                          addrinfo                      */ 
/*    memset                                Set the memory to 0           */
/*    freeaddrinfo                          Release addrinfo memory       */
/*    nx_dns_ipv4_address_by_name_get       Get ipv4 addr by name via dns */
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
/*  09-30-2020     Yuxin Zhou               Modified comment(s), improved */
/*                                            buffer length verification, */
/*                                            verified memcpy use cases,  */
/*                                            fixed compiler errors,      */
/*                                            resulting in version 6.1    */
/*  07-29-2022     Yuxin Zhou               Modified comment(s), and      */
/*                                            fixed compiler warnings,    */
/*                                            resulting in version 6.1.12 */
/*                                                                        */
/**************************************************************************/
INT  getaddrinfo(const CHAR *node, const CHAR *service, const struct addrinfo *hints, struct addrinfo **res)
{

UINT            status;
UINT            pton_flag;
UINT            port;
UINT            i, j;
INT             addr_family;
UINT            ipv4_addr_count = 0;
UINT            match_service_count;
UINT            match_service_socktype[3];
UINT            match_service_protocol[3];
struct addrinfo *addrinfo_cur_ptr  = NX_NULL;
struct addrinfo *addrinfo_head_ptr = NX_NULL;
struct addrinfo *addrinfo_tail_ptr = NX_NULL;
struct sockaddr *sockaddr_ptr      = NX_NULL;
UCHAR           *cname_buffer      = NX_NULL;

/* When hints is a null pointer, use the default value below. */
static struct addrinfo default_hints = {0, AF_UNSPEC, 0, 0, 0, NX_NULL, NX_NULL, NX_NULL};



    /* if node and service are null return an error, invalid input. */
    if((node == NX_NULL) && (service == NX_NULL))
        return EAI_NONAME;

    if(hints)
    {

        /* Check if the address family is valid. */
        if((hints -> ai_family != AF_INET)  &&
           (hints -> ai_family != AF_UNSPEC))
            return EAI_FAMILY;

        /* Check if the socket type is valid. */
        if((hints -> ai_socktype != SOCK_DGRAM)  &&
           (hints -> ai_socktype != SOCK_STREAM) &&
           (hints -> ai_socktype != 0))
            return EAI_SOCKTYPE;

        /* If socktype and protocol are both specified, check if they are meaningful. */
        if((hints -> ai_socktype != 0) && (hints -> ai_protocol != 0))
        {
            if(((hints -> ai_socktype == SOCK_STREAM) && (hints -> ai_protocol != IPPROTO_TCP)) ||
               ((hints -> ai_socktype == SOCK_DGRAM) && (hints -> ai_protocol != IPPROTO_UDP)))
                return EAI_SOCKTYPE;
        }

    }
    else
    {
        hints = &default_hints;
    }

    /* Sock type specified? */
    if(hints -> ai_socktype == 0)
    {

        /* No; is protocol specified? */
        if(hints -> ai_protocol == 0)
        {

            /* No, protocol is not specified. */

            /* Set default socktype and protocol. */
            match_service_count = 2;
            match_service_socktype[0] = SOCK_STREAM;
            match_service_protocol[0] = IPPROTO_TCP;
            match_service_socktype[1] = SOCK_DGRAM;
            match_service_protocol[1] = IPPROTO_UDP;
        }
        else
        {

            /* protocol is specified. */
            match_service_count = 1;
            match_service_protocol[0] = (UINT)(hints -> ai_protocol);

            /* Set default socktype according to protocol. */
            if(hints -> ai_protocol == IPPROTO_TCP)
                match_service_socktype[0] = SOCK_STREAM;
            else if(hints -> ai_protocol == IPPROTO_UDP)
                match_service_socktype[0] = SOCK_DGRAM;
        }
    }
    else
    {

        /* Socktype is specified. */
        match_service_count = 1;
        match_service_socktype[0] = (UINT)(hints -> ai_socktype);

        if(hints -> ai_protocol == 0)
        {

            /* Protocol is not specified. */

            /* Set default protocol according to socktype. */
            if(hints -> ai_socktype == SOCK_STREAM)
                match_service_protocol[0] = IPPROTO_TCP;
            else if(hints -> ai_socktype == SOCK_DGRAM)
                match_service_protocol[0] = IPPROTO_UDP;
        }
        else
        {

            /* Protocol is specififed. */
            match_service_protocol[0] = (UINT)(hints -> ai_protocol);
        }
    }

    if(service)
    {

        /* Service is not null. */
        if(bsd_string_to_number(service, &port) != NX_SOC_ERROR)
        {
            
            /* Service is a decimal port number string, and has been converted to a numeric port successfully. */

            /* Convert port from host byte order to network byte order. */
            port = htons((USHORT)port);
        }
        else
        {

            /* Service is an address name, not a decimal port number string. */

            /* Check if numeric service flag is set. If so this is an invalid string. */            
            if(hints -> ai_flags & AI_NUMERICSERV)
                return EAI_NONAME;

            match_service_count = 0;

            /* Look for a match of name, protocol and socket type for a match in the service list. */ 
            for(i = 0; i < _nx_bsd_serv_list_len; i++)            
            {

                /* Check if there is a match. */
                if(!memcmp(_nx_bsd_serv_list_ptr[i].service_name, service, _nx_bsd_string_length((CHAR *)service)) &&
                        ((_nx_bsd_serv_list_ptr[i].service_socktype == hints -> ai_socktype) ||(hints -> ai_socktype == 0)) &&
                        ((_nx_bsd_serv_list_ptr[i].service_protocol == hints -> ai_protocol) ||(hints -> ai_protocol == 0)))
                {
                    match_service_socktype[match_service_count] = (UINT)(_nx_bsd_serv_list_ptr[i].service_socktype);
                    match_service_protocol[match_service_count++] = (UINT)(_nx_bsd_serv_list_ptr[i].service_protocol);

                    /* Convert host byte order to network byte order. */
                    port = htons(_nx_bsd_serv_list_ptr[i].service_port);
                }
            }
            
            /* Service is not available. */
            if(match_service_count == 0)
                return EAI_SERVICE;
        }
    }
    else
    {

        /* Convert host byte order to network byte order. */
        port = htons(0);
    }

    if(node)
    {

        /* Node is not null. */

        /* Determine the address family. */
        addr_family = AF_INET;


        /* Initialize to 0, default to pton failing. */
        pton_flag = 0;

        if(addr_family == AF_INET)
        {

            /* Convert node from a string presentation to a numeric address. */
            if(inet_pton(addr_family, node, &(nx_bsd_ipv4_addr_buffer[0])) == 1)
            {
                /* pton has successful completion. */
                pton_flag = 1;

                /* Check if the address and the specified family match. */
                if((hints -> ai_family != AF_INET) && (hints -> ai_family != AF_UNSPEC))
                    return EAI_ADDRFAMILY;

                NX_CHANGE_ULONG_ENDIAN(nx_bsd_ipv4_addr_buffer[0]);
                ipv4_addr_count = 1;
            }
        }

        if(pton_flag == 1)
        {

            /* pton completed successfull. Host (node) is an address string. */

#if defined(NX_BSD_ENABLE_DNS) && defined (NX_DNS_ENABLE_EXTENDED_RR_TYPES)
            /* DNS supports extended services including Canonical name queries. */
            if((hints -> ai_flags & AI_CANONNAME) && !(hints -> ai_flags & AI_NUMERICHOST))
            {

                /* Allocate a block for canonical name. */
                status = tx_block_allocate(&nx_bsd_cname_block_pool, (VOID *) &cname_buffer, NX_BSD_TIMEOUT);

                /* Check for error status.  */
                if (status != TX_SUCCESS)
                {
                    /* Set the error. */
                    set_errno(ENOMEM); 

                    /* Error getting NetX socket memory.  */
                    NX_BSD_ERROR(NX_BSD_BLOCK_POOL_ERROR, __LINE__);

                    /* Return memory allocation error. */
                    return(EAI_MEMORY); 
                }

                /* Verify buffer size. */
                if (_nx_bsd_string_length((CHAR *)node) > NX_DNS_NAME_MAX)
                    return(EAI_OVERFLOW);

                memcpy(cname_buffer, node, _nx_bsd_string_length((CHAR *)node)); /* Use case of memcpy is verified. */

            }
#endif /* NX_BSD_ENABLE_DNS && NX_DNS_ENABLE_EXTENDED_RR_TYPES */

        }
        else
        {

            /* Presentation to numeric format fails, node may be a hostname, not a numeric IP address. */

            /* Check if numeric host flag is set. */
            if(hints -> ai_flags & AI_NUMERICHOST)
                return EAI_NONAME;

#ifdef NX_BSD_ENABLE_DNS
            if(hints -> ai_family == AF_INET)
            {

                /* Get IPv4 address by hostname. */
                status = nx_dns_ipv4_address_by_name_get(_nx_dns_instance_ptr, (UCHAR *)node, &nx_bsd_ipv4_addr_buffer[0], 
                                                         NX_BSD_IPV4_ADDR_PER_HOST * 4, &ipv4_addr_count, NX_BSD_TIMEOUT);

                if(status != NX_SUCCESS)
                {

                    /* Just return EAI_FAIL, because we can't discriminate between DNS FAIL and the situation where the specified 
                       network host exists but does not have any network addresses defined. It would be better to return EAI_FAIL 
                       for DNS FAIL, and EAI_NODATA for the latter situation. */
                    return EAI_FAIL;
                }
            }
            else 
            {

                /* Address family is not specified. Query for IPv4 address. */

                /* Get IPv4 address by hostname. */
                status = nx_dns_ipv4_address_by_name_get(_nx_dns_instance_ptr, (UCHAR *)node, &nx_bsd_ipv4_addr_buffer[0], 
                                                         NX_BSD_IPV4_ADDR_PER_HOST * 4, &ipv4_addr_count, NX_BSD_TIMEOUT);

                if(status != NX_SUCCESS)
                {
                    /* Just return EAI_FAIL, because we can't discriminate between DNS FAIL and the situation that the specified 
                       network host exists, but does not have any network addresses defined. It would be better to return EAI_FAIL 
                       for DNS FAIL, and EAI_NODATA for the latter situation. */
                    return EAI_FAIL;
                }
            }

            if(hints -> ai_flags & AI_CANONNAME)
            {

#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
                /* Allocate a block for canonical name. */
                status = tx_block_allocate(&nx_bsd_cname_block_pool, (VOID *) &cname_buffer, NX_BSD_TIMEOUT);

                /* Check for error status.  */
                if (status != TX_SUCCESS)
                {
                    /* Set the error. */
                    set_errno(ENOMEM); 

                    /* Error getting NetX socket memory.  */
                    NX_BSD_ERROR(NX_BSD_BLOCK_POOL_ERROR, __LINE__);

                    /* Return memory allocation error. */
                    return(EAI_MEMORY); 
                }

                status = nx_dns_cname_get(_nx_dns_instance_ptr, (UCHAR *)node, cname_buffer, 
                                          nx_bsd_cname_block_pool.tx_block_pool_block_size, NX_BSD_TIMEOUT);
                if(status != NX_SUCCESS)
                {

                    /* Verify buffer size. */
                    if (_nx_bsd_string_length((CHAR *)node) > NX_DNS_NAME_MAX)
                        return(EAI_OVERFLOW);

                    memcpy(cname_buffer, node, _nx_bsd_string_length((CHAR *)node)); /* Use case of memcpy is verified. */
                }

#else
                cname_buffer = (UCHAR *)node;
#endif
            }
#else
            return EAI_FAIL;
#endif

        }
    }
    else
    {

        /* Node is null. */
        if(hints -> ai_flags & AI_PASSIVE)
        {
            /* The caller wiil use the socket for a passive open. */

            nx_bsd_ipv4_addr_buffer[0] = INADDR_ANY;

        }
        else
        {

            /* Localhost address. */
            nx_bsd_ipv4_addr_buffer[0] = 0x7F000001;

        }

        {
            ipv4_addr_count = 1;
        }
    }


    for(i = 0; i < ipv4_addr_count; i++)
    {

        /* Allocate a block for ipv4 address. */
        status = tx_block_allocate(&nx_bsd_addrinfo_block_pool, (VOID *) &sockaddr_ptr, NX_BSD_TIMEOUT);

        /* Check for error status.  */
        if (status != TX_SUCCESS)
        {

            /* Set the error. */
            set_errno(ENOMEM); 

            /* If head is not null, free the memory. */
            if(addrinfo_head_ptr)
                freeaddrinfo(addrinfo_head_ptr);

#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
            if(hints -> ai_flags & AI_CANONNAME)
                tx_block_release((VOID *)cname_buffer);
#endif

            /* Error getting NetX socket memory.  */
            NX_BSD_ERROR(NX_BSD_BLOCK_POOL_ERROR, __LINE__);
            
            /* Return memory allocation error. */
            return(EAI_MEMORY); 
        }

        /* Clear the  memory.  */
        memset((VOID*)sockaddr_ptr, 0, sizeof(struct addrinfo));

        if(i < ipv4_addr_count)
        {

            /* Process IPv4 address. */
            ((struct sockaddr_in*)sockaddr_ptr) -> sin_family = AF_INET;
            ((struct sockaddr_in*)sockaddr_ptr) -> sin_port   = (USHORT)port;
            ((struct sockaddr_in*)sockaddr_ptr) -> sin_addr.s_addr = nx_bsd_ipv4_addr_buffer[i];
            
            NX_CHANGE_ULONG_ENDIAN(((struct sockaddr_in*)sockaddr_ptr) -> sin_addr.s_addr);
        }

        for(j = 0; j < match_service_count; j++)
        {

            /* Allocate a block from the addrinfo block pool. */
            status = tx_block_allocate(&nx_bsd_addrinfo_block_pool, (VOID *) &addrinfo_cur_ptr, NX_BSD_TIMEOUT);

            /* Check for error status.  */
            if (status != TX_SUCCESS)
            {

                /* Set the error. */
                set_errno(ENOMEM); 

                /* If head is not null, free the memory. */
                if(addrinfo_head_ptr)
                    freeaddrinfo(addrinfo_head_ptr);

                tx_block_release((VOID *)sockaddr_ptr);

#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
                if(hints -> ai_flags & AI_CANONNAME)
                    tx_block_release((VOID *)cname_buffer);
#endif

                /* Error getting NetX socket memory.  */
                NX_BSD_ERROR(NX_BSD_BLOCK_POOL_ERROR, __LINE__);

                /* Return memory allocation error. */
                return(EAI_MEMORY); 
            }

            /* Clear the socket memory.  */
            memset((VOID*)addrinfo_cur_ptr, 0, sizeof(struct addrinfo));
            
            if(i < ipv4_addr_count)
            {

                /* IPv4 */
                addrinfo_cur_ptr -> ai_family  = AF_INET;
                addrinfo_cur_ptr -> ai_addrlen = sizeof(struct sockaddr_in);
            }
            
            addrinfo_cur_ptr -> ai_socktype = (INT)(match_service_socktype[j]);
            addrinfo_cur_ptr -> ai_protocol = (INT)(match_service_protocol[j]);
            addrinfo_cur_ptr -> ai_addr = sockaddr_ptr;
            if((i == 0) && (j == 0) && (hints -> ai_flags & AI_CANONNAME))
                addrinfo_cur_ptr -> ai_canonname = (CHAR *)cname_buffer;
            else
                addrinfo_cur_ptr -> ai_canonname = NX_NULL;
            addrinfo_cur_ptr -> ai_next = NX_NULL;

            /* Make a list. */
            if(addrinfo_head_ptr == NX_NULL)
                addrinfo_head_ptr = addrinfo_cur_ptr;
            else
                addrinfo_tail_ptr -> ai_next = addrinfo_cur_ptr;

            addrinfo_tail_ptr = addrinfo_cur_ptr;

        }
    }

    *res = addrinfo_head_ptr;
    
    return 0;
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    freeaddrinfo                                        PORTABLE C      */ 
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function releases the memory allocated by getaddrinfo.         */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    res                                   Pointer to a addrinfo struct  */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */ 
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    tx_block_release                      Release socket memory         */ 
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
VOID freeaddrinfo(struct addrinfo *res)
{

struct addrinfo *next_addrinfo;
struct sockaddr *ai_addr_ptr = NX_NULL;
#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
CHAR *ai_canonname_ptr = NX_NULL;
#endif

    while(res)
    {
#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
        if((res -> ai_canonname) &&
           (res -> ai_canonname != ai_canonname_ptr))
        {

            /* Release  the CNAME memory. */
            tx_block_release((VOID *)res -> ai_canonname);
            
            ai_canonname_ptr = res -> ai_canonname;
        }
#endif
        if((res -> ai_addr) &&
           (res -> ai_addr != ai_addr_ptr))
        {

            /* Release the address memory. */
            tx_block_release((VOID *)res -> ai_addr);
            
            ai_addr_ptr = res -> ai_addr;
        }

        /* Move next. */
        next_addrinfo = res -> ai_next;

        /* Release the addrinfo memory. */
        tx_block_release((VOID *)res);

        res = next_addrinfo;
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    bsd_string_to_number                                PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function converts string to number.                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    string                                Pointer to a string           */
/*    number                                Pointer to a number           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                                              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_bsd_isdigit                        Indicate char is a number     */
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
static INT bsd_string_to_number(const CHAR *string, UINT *number)
{

    /* Initialize the numbet to zero. */
    *number = 0;

    while(*string != '\0')
    {

        /* Check if the current character is a digit character. */
        if(!nx_bsd_isdigit((UCHAR)(*string)))
            return NX_SOC_ERROR;

        *number = (*number * 10) + (UINT)(*string - 0x30);
   
        string++;
    }

    return NX_SOC_OK;
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    getnameinfo                                         PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function converts a socket address to a corresponding host and */
/*    service.                                                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    sa                                   Pointer to a generic socket    */
/*                                           address structure            */
/*    salen                                Length of sa structure         */
/*    host                                 Pointer to caller-allocated    */
/*                                           buffer for hostname          */
/*    hostlen                              Host buffer size               */
/*    serv                                 Pointer to caller-allocated    */
/*                                           buffer for service name      */
/*    servlen                              Service buffer size            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               0 if OK, nonzero on errors     */ 
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_dns_host_by_address_get           Get hostname by IPv4 address   */
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
/*  09-30-2020     Yuxin Zhou               Modified comment(s), and      */
/*                                            verified memcpy use cases,  */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
INT  getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen, char *serv, size_t servlen, int flags)
{

UINT        i = 0;
/* Flag used to identify whether host/service is numeric, 0 no, 1 yes. */
UINT        numeric_flag;
USHORT     *temp;
#ifdef NX_BSD_ENABLE_DNS          
UINT        status;
#endif
const CHAR  *rt_ptr;

    if(!sa)
    {

        /* sa is NULL. */
        return EAI_FAMILY;
    }
    else 
    {
        if(sa -> sa_family != AF_INET) 
        {

            /* sa isn't NULL, but family type is invalid. */
            return EAI_FAMILY;
        }
        else if(sa -> sa_family == AF_INET && salen != sizeof(struct sockaddr_in))
        {

            /* Address length is invalid. */
            return EAI_FAMILY;
        }
    }

    /* Both host and service null are invalid */
    if((host == NX_NULL) && (serv == NX_NULL) && ((flags & NI_NAMEREQD) == 0))
        return EAI_NONAME;

    if(serv && servlen > 0)
    {      
        numeric_flag = 1;

        /* If NUMERICSERV bit is set, set to 1. */
        if(flags & NI_NUMERICSERV)
        {
            numeric_flag = 1;
        }
        else if(flags & NI_DGRAM)
        {
            /* Socket type must be SOCK_DGRAM. */

            for(i = 0; i < _nx_bsd_serv_list_len; i++)
            {
                temp = (USHORT *)(sa -> sa_data);
                if((_nx_bsd_serv_list_ptr[i].service_port == *temp) &&
                   (_nx_bsd_serv_list_ptr[i].service_socktype == SOCK_DGRAM))
                {

                    /* Found a matched service, set numeric flag to 0. */
                    numeric_flag = 0;
                    break;
                }
            }
        }
        else 
        {

            /* Socket type is SOCK_STREAM. */
            for(i = 0; i < _nx_bsd_serv_list_len; i++)
            {
                temp = (USHORT *)(sa -> sa_data);
                if((_nx_bsd_serv_list_ptr[i].service_port == *temp) &&
                   (_nx_bsd_serv_list_ptr[i].service_socktype == SOCK_STREAM))
                {

                    /* Found a matched service, set numeric flag to 0. */
                    numeric_flag = 0;
                    break;
                }
            }
        }

        if(numeric_flag)
        {

            /* Service is numeric, copy the service port. Then convert host byte order to network byte order. */
            temp = (USHORT *)(sa -> sa_data);
            if(bsd_number_convert(htons(*temp), (CHAR *)serv, servlen, 10) == 0)
                return EAI_OVERFLOW;
        }
        else
        {

            /* Service isn't numeric, copy the service name. */
            if(_nx_bsd_string_length(_nx_bsd_serv_list_ptr[i].service_name) > servlen)
                return EAI_OVERFLOW;

            memcpy(serv, _nx_bsd_serv_list_ptr[i].service_name, /* Use case of memcpy is verified. */
                   _nx_bsd_string_length(_nx_bsd_serv_list_ptr[i].service_name));
        }
    }

    if(host && hostlen > 0)
    {
        numeric_flag = 1;

        /* If NUMERIC bit is set, set flag to 1. */
        if(flags & NI_NUMERICHOST)
            numeric_flag = 1;
        else
        {

#ifdef NX_BSD_ENABLE_DNS          
            if(sa -> sa_family == AF_INET)
            {

                /* Get host name by IPv4 address via DNS. */
                status = nx_dns_host_by_address_get(_nx_dns_instance_ptr, ntohl(((struct sockaddr_in *)sa) -> sin_addr.s_addr), 
                                                    (UCHAR *)host, hostlen, NX_BSD_TIMEOUT);
            }
            else
            {
                status = NX_DNS_NO_SERVER;
            }


            if(status == NX_DNS_SIZE_ERROR)
                return EAI_OVERFLOW;
            else if(status != NX_SUCCESS)
            {

                /* DNS query fails. */
                if(flags & NI_NAMEREQD)
                    return EAI_NONAME;
            }
            else
            {

                /* DNS query succeeds. */
                numeric_flag = 0;
            }
#else
            if(flags & NI_NAMEREQD)
                return EAI_NONAME;
#endif
        }

        if(numeric_flag)
        {

            /* Host must be numeric string. Convert IP address from numeric to presentation. */
                rt_ptr = inet_ntop(AF_INET, &((struct sockaddr_in*)sa) -> sin_addr, (CHAR *)host, hostlen);
            
            if(!rt_ptr)
                return EAI_OVERFLOW;
        }

    }

    return 0;
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_bsd_set_service_list                             PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function lets user set the service list used by getaddrinfo    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    serv_list_ptr                        Pointer to a service list      */
/*    serv_list_len                        Service list length            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */ 
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
VOID nx_bsd_set_service_list(struct NX_BSD_SERVICE_LIST *serv_list_ptr, ULONG serv_list_len)
{
    _nx_bsd_serv_list_ptr = serv_list_ptr;
    _nx_bsd_serv_list_len = serv_list_len;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_bsd_string_length                               PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function returns the length of string.                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    string                               Pointer to a string            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    ULONG                                String length                  */ 
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX BSD Layer Source Code                                          */ 
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
static ULONG _nx_bsd_string_length(CHAR * string)
{
int length = 0;

    while(*string != '\0')
    {
        length++;
        string++;
    }

    return((ULONG)length);
    
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_bsd_fast_periodic_timer_entry                   PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles BSD system clock. When the timer expires, the */
/*    BSD system clock is updated and then default IP fast periodic entry */
/*    routine is invoked.                                                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    id                                   Argument of default timer entry*/
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */ 
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    None                                                                */ 
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
static VOID  _nx_bsd_fast_periodic_timer_entry(ULONG id)
{

    /* Update the BSD system clock. */
    nx_bsd_system_clock += nx_bsd_timer_rate;

    /* Call default IP fast periodic timer entry. */
    nx_bsd_ip_fast_periodic_timer_entry(id);
}
