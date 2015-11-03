/*
-----------------------------------------------------------------------------
 $Id: tsp_tun.c,v 1.1 2009/11/20 16:53:20 jasminko Exp $
-----------------------------------------------------------------------------
Copyright (c) 2001-2006 gogo6 Inc. All rights reserved.

  For license information refer to CLIENT-LICENSE.TXT
  
-----------------------------------------------------------------------------
*/

/* Darwin */

#include "platform.h"
#include "gogoc_status.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "tsp_tun.h"        // Local function prototypes.
#include "tsp_client.h"     // tspCheckForStopOrWait()
#include "net_ka.h"         // KA function prototypes and types.
#include "log.h"            // Display and logging prototypes and types.
#include "hex_strings.h"    // String litterals

#define TUN_BUFSIZE 2048    // Buffer size for TUN interface IO operations.



// --------------------------------------------------------------------------
// TunName: Get the name of the tun device using file descriptor.
//
void TunName(int tunfd, char *name, size_t name_len )
{
  struct stat sbuf;
  char *unsafe_buffer;

  if( fstat( tunfd, &sbuf ) != -1 )
  {
    unsafe_buffer = devname(sbuf.st_rdev, S_IFCHR);
    strncpy( name, unsafe_buffer, name_len );
  }
}


// --------------------------------------------------------------------------
// TunInit: Open and initialize the TUN interface.
//
int TunInit( char* name )
{
  struct sockaddr_ctl sc;
  struct ctl_info ctlInfo;
  int tunfd;
  int utunnum = 0; 
  char iftun[128];

  //snprintf( iftun, sizeof(iftun), "/dev/%s", name );
  snprintf( iftun, sizeof(iftun), "%s", name );
  if (!sscanf (iftun , "utun%d", &utunnum)==1)
  {
    Display(LOG_LEVEL_1, ELError, "TunInit", GOGO_STR_ERR_PARSE_UTUN_DEV, iftun);
    // FIXME: if the device name is wrong, gogoc won't work anyway.
    snprintf( iftun, sizeof(iftun), "%s", "utun0");
  }
  //
  //tunfd = open( iftun, O_RDWR );
  memset(&ctlInfo, 0, sizeof(ctlInfo));
    if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
      sizeof(ctlInfo.ctl_name)) {
        fprintf(stderr,"UTUN_CONTROL_NAME too long");
          return -1;
	}
    tunfd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

  if( tunfd == -1 )
  {
    Display(LOG_LEVEL_1, ELError, "TunInit", GOGO_STR_ERR_OPEN_TUN_DEV, iftun);
    return(-1);
  }
  if (ioctl(tunfd, CTLIOCGINFO, &ctlInfo) == -1) {
    Display(LOG_LEVEL_1, ELError, "TunInit", GOGO_STR_ERR_CTLIOCGINFO_OPEN_TUN_DEV, iftun);
    //perror ("ioctl(CTLIOCGINFO)");
    close(tunfd);
    return -1;
  }

  sc.sc_id = ctlInfo.ctl_id;
  sc.sc_len = sizeof(sc);
  sc.sc_family = AF_SYSTEM;
  sc.ss_sysaddr = AF_SYS_CONTROL;
  sc.sc_unit = utunnum +1;

  if (connect(tunfd, (struct sockaddr *)&sc, sizeof(sc)) == -1) {
    Display(LOG_LEVEL_1, ELError, "TunInit", GOGO_STR_ERR_CTLIOCGINFO_OPEN_TUN_DEV, iftun);
    //perror ("connect(AF_SYS_CONTROL)");
    close(tunfd);
    return -1;
  }

  Display(LOG_LEVEL_1, ELError, "TunInit", "%s created", iftun);
  return tunfd;
}

// --------------------------------------------------------------------------
// TunMainLoop: Initializes Keepalive engine and starts it. Then starts a
//   loop to transfer data from/to the socket and tunnel.
//   This process is repeated until tspCheckForStopOrWait indicates a stop.
//
gogoc_status TunMainLoop( int tunfd,
                         pal_socket_t Socket,
                         tBoolean keepalive,
                         int keepalive_interval,
                         char *local_address_ipv6,
                         char *keepalive_address )
{
  fd_set rfds;
  int count, maxfd, ret;
  char bufin[TUN_BUFSIZE];
  char bufout[TUN_BUFSIZE];
  struct timeval timeout;
  void* p_ka_engine = NULL;
  ka_status_t ka_status;
  ka_ret_t ka_ret;
  int ongoing = 1;
  gogoc_status status;


  keepalive = (keepalive_interval != 0) ? TRUE : FALSE;

  if( keepalive == TRUE )
  {
    // Initialize the keepalive engine.
    ka_ret = KA_init( &p_ka_engine, keepalive_interval * 1000,
                      local_address_ipv6, keepalive_address, AF_INET6 );
    if( ka_ret != KA_SUCCESS )
    {
      return make_status(CTX_TUNNELLOOP, ERR_KEEPALIVE_ERROR);
    }

    // Start the keepalive loop(thread).
    ka_ret = KA_start( p_ka_engine );
    if( ka_ret != KA_SUCCESS )
    {
      KA_destroy( &p_ka_engine );
      return make_status(CTX_TUNNELLOOP, ERR_KEEPALIVE_ERROR);
    }
  }

  // tun device wants bufin[0]...[3] to contain AF_INET6
  ((u_int32_t *)bufin)[0] = htonl(AF_INET6);


  // Data send loop.
  while( ongoing == 1 )
  {
    // initialize status.
    status = STATUS_SUCCESS_INIT;

    if( tspCheckForStopOrWait( 0 ) != 0 )
    {
      // We've been notified to stop.
      ongoing = 0;
    }

    if( keepalive == TRUE )
    {
      // Check if we're stopping.
      if( ongoing == 0 )
      {
        // Stop keepalive engine.
        KA_stop( p_ka_engine );
      }

      // Query the keepalive status.
      ka_status = KA_qry_status( p_ka_engine );
      switch( ka_status )
      {
      case KA_STAT_ONGOING:
      case KA_STAT_FIN_SUCCESS:
        break;

      case KA_STAT_FIN_TIMEOUT:
        KA_stop( p_ka_engine );
        status = make_status(CTX_TUNNELLOOP, ERR_KEEPALIVE_TIMEOUT);
        break;

      case KA_STAT_INVALID:
      case KA_STAT_FIN_ERROR:
      default:
        KA_stop( p_ka_engine );
        status = make_status(CTX_TUNNELLOOP, ERR_KEEPALIVE_ERROR);
        break;
      }

      // Reinit select timeout variable; select modifies it.
      // Use 500ms because we need to re-check keepalive status.
      timeout.tv_sec = 0;
      timeout.tv_usec = 500000;    // 500 milliseconds.
    }
    else
    {
      // Reinit select timeout variable; select modifies it.
      timeout.tv_sec = 7 * 24 * 60 * 60 ; // one week
      timeout.tv_usec = 0;
    }


    // Check if we're normal.
    if( status_number(status) != SUCCESS  ||  ongoing != 1 )
    {
      goto done;
    }

    FD_ZERO(&rfds);
    FD_SET(tunfd,&rfds);
    FD_SET(Socket,&rfds);

    maxfd = tunfd>Socket?tunfd:Socket;

    ret = select( maxfd+1, &rfds, 0, 0, &timeout );
    if (ret > 0)
    {
      if( FD_ISSET(tunfd, &rfds) )
      {
        // Data sent through UDP tunnel.
        /* ioctl(tunfd, FIONREAD, &count); */
        if ((count = read(tunfd, bufout, TUN_BUFSIZE)) < -1)
        {
          Display(LOG_LEVEL_1, ELError, "TunMainLoop", STR_NET_FAIL_R_TUN_DEV);
          status = make_status(CTX_TUNNELLOOP, ERR_TUNNEL_IO);
          goto done;
        }

        if (send(Socket, bufout+4, count-4, 0) != count-4)
        {
          Display(LOG_LEVEL_1, ELError, "TunMainLoop", STR_NET_FAIL_W_SOCKET);
          status = make_status(CTX_TUNNELLOOP, ERR_TUNNEL_IO);
          goto done;
        }
      }

      if(FD_ISSET(Socket,&rfds))
      {
        // Data received through UDP tunnel.
        count = recvfrom( Socket, bufin +4, TUN_BUFSIZE -4, 0, NULL, NULL );
        if (write(tunfd, bufin, count +4) != count +4)
        {
          Display(LOG_LEVEL_1, ELError, "TunMainLoop", STR_NET_FAIL_W_TUN_DEV);
          status = make_status(CTX_TUNNELLOOP, ERR_TUNNEL_IO);
          goto done;
        }
      }
    }

  } // while ongoing == 1

  /* Normal loop end */
  status = STATUS_SUCCESS_INIT;

done:
  if( keepalive == TRUE )
  {
    KA_destroy( &p_ka_engine );
  }

  return status;
}

