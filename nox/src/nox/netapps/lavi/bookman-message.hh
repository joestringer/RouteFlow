#ifndef BOOKMAN_MSG_HH__
#define BOOKMAN_MSG_HH__

#include <stdint.h>
#include <stdlib.h>
#include "openflow/openflow/openflow.h"
#include "messenger/message.hh"

/**************************************************
 * Main message type
 **************************************************/

/** Types of query/reply to send/receive.
 */
enum book_type
{
  /** Disconnection message.
   * Need to be consistent with messenger.
   */
  BOOKT_DISCONNECT = MSG_DISCONNECT,
  /** Echo message.
   * Need to be consistent with messenger.
   */
  BOOKT_ECHO = MSG_ECHO,
  /** Response message.
   */
  BOOKT_ECHO_RESPONSE = MSG_ECHO_RESPONSE,
  /** Authentication.
   * Need to be consistent with messenger.
   */
  BOOKT_AUTH = MSG_AUTH,
  /** Authenication response.
   * Need to be consistent with messenger.
   * Need to be consistent.
   */
  BOOKT_AUTH_RESPONSE = MSG_AUTH_RESPONSE,
  /** Authentication status.
   * Need to be consistent with messenger.
   */
  BOOKT_AUTH_STATUS = MSG_AUTH_STATUS,

  /** Poll registration.
   * Body is \ref book_poll_message.
   */
  BOOKT_POLL = 0x0E,
  /** Poll deregistration.
   * Body is \ref book_poll_stop_message.
   */
  BOOKT_POLL_STOP = 0x0F,


  /** Query for list of nodes.
   * Body is uint16_t (book_node_req_message)
   */
  BOOKT_NODES_REQ = 0x10,
  /** Reply with list of nodes added.
   * Body is array of book_node.
   * xid is zero for switch addition due to subscription for update.
   */
  BOOKT_NODES_ADD = 0x11,
  /** Reply with list of switches deleted.
   * Body is array of book_node.
   * xid is zero for switch deletion due to subscription for update.
   */
  BOOKT_NODES_DEL = 0x12,
  /** Query for list of links for the specified switch.
   * Body is book_link_req_message.
   */
  BOOKT_LINKS_REQ = 0x13,
  /** Reply with list of links added.
   * Body is \ref book_link_rate_message.
   */
  BOOKT_LINKS_ADD = 0x14,
  /** Reply with list of links deleted.
   * Body is \ref book_link_message.
   */
  BOOKT_LINKS_DEL = 0x15,
  /** Query for flows.
   * Body is \ref book_flow_req_message.
   */
  BOOKT_FLOWS_REQ = 0x16,
  /** Reply with list of flows added.
   * Body is \ref book_flow_message.
   */
  BOOKT_FLOWS_ADD = 0x17,
  /** Reply with list of flows deleted.
   * Body is \ref book_flow_message.
   */
  BOOKT_FLOWS_DEL = 0x18,

  /** Statistics request.
   * Body is \ref book_stat_message, with osr_body
   * as defined in OpenFlow for ofp_stats_request.
   */
  BOOKT_STAT_REQ = 0x20,
  /** Statistics reply.
   * Body is \ref book_stat_message, with osr_body
   * as defined for ofp_stats_reply in OpenFlow.
   */
  BOOKT_STAT = 0x21,

  /**
   * messages for extra
   * communication with aggregation GUI
   */


  /* the user (gui) requests a new bundle */
  BOOKT_BUNDLE_REQ = 0x30,

  /* inform back the user for the ID of
   * a new bundle */
  BOOKT_BUNDLE_REPLY = 0x31,

  /* request from the GUI to modify a bundle */
  BOOKT_BUNDLE_MODIFY = 0x33,

  /* request from the GUI to delete a bundle */
  BOOKT_BUNDLE_DELETE = 0x34,

  /* request for aggregation updates */
  BOOKT_AGGR_REQ = 0x35,

  /* aggregation related statistics */
  BOOKT_BUNDLE_STATS = 0x36,

  /* delete all bundles at the controller (for desynchronized GUI) */
  BOOKT_AGGR_DEL_ALL = 0x37,

  /* that's ugly : block traffic for demo purposes */
  BOOKT_AGGR_BLOCK_TRAFFIC = 0x38,

  /* that's ugly : allow full traffic for demo purposes */
  BOOKT_AGGR_FULL_TRAFFIC = 0x39,

  /* delete all state related with the aggregation demo */
  BOOKT_AGGR_CLEAR = 0x3A,

  /**
   * messages for extra
   * communication with MPLS-TE GUI
   */

  /* request for creating preconfigured TE tunnels */
  BOOKT_MPLS_CONF_TUNN_REQ = 0x50,

  /* request for dynamically creating TE tunnel */
  BOOKT_MPLS_DYN_TUNN_REQ = 0x51,

  /* reply to configured or dynamic TUNN_REQ */
  BOOKT_MPLS_TUNN_REPLY = 0x52,

  /* tunnel stats */
  BOOKT_MPLS_STATS = 0x53,


};


/** \brief Header for \ref book_message.
 *
 * Note this is made consistent with messenger_msg for the
 * disconnect message, which is handled by messenger_core
 *
 */
struct book_header
{
  /** \brief Length of message to send.
   *
   * To include this header.
   */
  uint16_t length;
  /** \brief Type of query, defined by \ref book_type.
   */
  uint8_t type;
  /** \brief Transaction id associated with query.
   *
   * Also used for querying of switches in NOX.
   * Default to zero for lavi initiated messages to bookman.
   * Each message should have an unique xid.  This field is used
   * to record state of the requests.
   */
  uint32_t xid;
} __attribute__ ((packed));

/** \brief Query/Reply for communication with \ref vigil::bookman.
 *
 * Copyright (C) Stanford University, 2008.
 * @date December 2008
 * @author ykk
 */
struct book_message
{
  /** Header.
   */
  book_header header;
  /** \brief Body of query/reply.
   *
   * Length is inferred by the length field in the header.
   */
  uint8_t body[0];
} __attribute__ ((packed));


/**************************************************
 * Requests
 **************************************************/

/** Type of requests
 */
enum book_req_type
{
  /** One time request.
   */
  BOOKR_ONETIME=0x01,
  /** Subscribe.
   */
  BOOKR_SUBSCRIBE=0x02,
  /** Unsubscribe.
   */
  BOOKR_UNSUBSCRIBE=0x03,
};

/** \brief Body part is the message that periodic posting is
 * desired.
 *
 * Note that the length and xid field of the
 * message in the body will be ignored.  Poll interval
 * of zero will be ignored.  Also, a poll
 * message is not allowed within a poll message.
 *
 * Copyright (C) Stanford University, 2009.
 * @date December 2008
 * @author ykk
 */
struct book_poll_message
{
  /** Poll interval in 0.1 second.
   */
  uint16_t pollInterval;
  /** Body of message to poll.
   */
  uint8_t body[0];
} __attribute__ ((packed));

/** \brief Message to remove polling.
 *
 * Copyright (C) Stanford University, 2008.
 * @date December 2008
 * @author ykk
 */
struct book_poll_stop_message
{
  /** xid to remove.
   */
  uint32_t xid;
} __attribute__ ((packed));

/**************************************************
 * Nodes
 **************************************************/

/** Types of nodes.
 */
enum book_node_type
{
  /** Everything or Unknown.
   */
  BOOKN_UNKNOWN = 0x0000,
  /** Generic OpenFlow Switch
   */
  BOOKN_OPENFLOW = 0x0001,
  /** Generic Wireless OpenFlow Switch
   */
  BOOKN_WIRELESS_OPENFLOW = 0x0002,

  /** Generic Host
   */
  BOOKN_HOST = 0x0100,
  /** Generic Wireless Host
   */
  BOOKN_WIRELESS_HOST = 0x0101,

  /** Generic NEC OpenFlow Switch
   */
  BOOKN_NEC_SWITCH = 0x1000,
  /** NEC IP8800 OpenFlow Switch
   */
  BOOKN_NEC_IP8800 = 0x1001,

  /** Generic HP OpenFlow Switch
   */
  BOOKN_HP_SWITCH = 0x1100,

  /** Ciena CoreDirector OpenFlow Switch
   */
  BOOKN_CIENA_SWITCH = 0x1200,

  /** Pronto OpenFlow Switch
   */
  BOOKN_PRONTO_SWITCH = 0x1300,

};

/** \brief Structure for node.
 *
 * Copyright (C) Stanford University, 2009.
 * @date April 2009
 * @author ykk
 */
struct book_node
{
  /** Constructor
   * @param type_ type of node
   * @param id_ identifier for node
   */
  book_node(uint16_t type_, uint64_t id_)
  {
    type = type_;
    id = id_;
  }

  /** Node type, member of book_node_type
   */
  uint16_t type;
  /** Node identifier.
   * Recommmendation:
   * Datapath ID for OpenFlow switches;
   * mac address for hosts
   */
  uint64_t id;
} __attribute__ ((packed));

/** \brief Body part of \ref book_message for
 * BOOKT_NODES_REQ messages.
 *
 * Copyright (C) Stanford University, 2009.
 * @date April 2009
 * @author ykk
 */
struct book_node_req_message
{
  /** Type of request, from book_req_type
   */
  uint8_t type;
  /** Node type.
   */
  uint16_t nodeType;
} __attribute__ ((packed));

/**************************************************
 * Links
 **************************************************/

/** Types of links.
 */
enum book_link_type
{
  /** Everything or Unknown.
   */
  BOOKL_UNKNOWN = 0x0000,
  /** Switch to switch.
   */
  BOOKL_SW2SW = 0x0001,

  BOOKL_TUNNEL = 0x0004,

  BOOKL_CIRCUIT = 0x0005,

  BOOKL_PACKET = 0x0006,

};


/** \brief Structure to specify a link
 *
 * Copyright (C) Stanford University, 2008.
 * @date December 2008
 * @author ykk
 */

struct book_link_spec
{
  /** Constructor.
   * @param type_ type of link
   * @param src source node
   * @param srcport source port number
   * @param dst destination node
   * @param dstport destination port number
   */
  book_link_spec(uint16_t type_, book_node src, uint16_t srcport,
		 book_node dst, uint16_t dstport):
    src_node(src), dst_node(dst)
  {
    type = type_;
    src_port = srcport;
    dst_port = dstport;
  }

  /** Link type, member of book_link_type
   */
  uint16_t type;
  /** Source node.
   */
  book_node src_node;
  /** Port number on source.
   */
  uint16_t src_port;
  /** Destination node.
   */
  book_node dst_node;
  /** Port number on destination.
   */
  uint16_t dst_port;
} __attribute__ ((packed));

/** \brief Structure to specify a link with rate
 *
 * Copyright (C) Stanford University, 2009.
 * @date May 2009
 * @author ykk
 */
struct book_link_rate_spec
{
  /** Link spec only.
   */
  book_link_spec bls;
  /** Data rate in Mbps?
   */
  uint64_t rate;

  uint8_t tunncolor;
} __attribute__ ((packed));

/** \brief Body part of \ref book_message for
 * BOOKT_LINKS_REQ messages.
 *
 * Copyright (C) Stanford University, 2009.
 * @date January 2009
 * @author ykk
 */
struct book_link_req_message
{
  /** Type of request, from book_req_type
   */
  uint8_t type;
  /** Type of link.
   */
  uint16_t linkType;
  /** Node type and id.
   * Not used for subscribe or unsubscribe.
   */
  book_node nodeTypeId;
} __attribute__ ((packed));

/** \brief Body part of \ref book_message for
 * BOOKT_LINKS_ADD messages.
 *
 * Copyright (C) Stanford University, 2009.
 * @date May 2009
 * @author ykk
 */
struct book_link_rate_message
{
  /** Array of book_link_rate_spec.
   */
  book_link_spec body[0];
} __attribute__ ((packed));


/** \brief Body part of \ref book_message for
 * BOOKT_LINKS_DEL messages.
 *
 * Copyright (C) Stanford University, 2009.
 * @date January 2009
 * @author ykk
 */
struct book_link_message
{
  /** Array of book_link_spec.
   */
  book_link_spec body[0];
} __attribute__ ((packed));

/**************************************************
 * Flows
 **************************************************/

/** Types of flows.
 */
enum book_flow_type
{
  /** Everything or Unknown.
   */
  BOOKF_UNKNOWN = 0x0000,

  BOOKF_CFLOW = 0x0001,

  BOOKF_PFLOW = 0x0002,

  BOOKF_TEMP = 0x0003
};

/** \brief Structure to specify node and port pair
 *
 * Copyright (C) Stanford University, 2009.
 * @date May 2009
 * @author dgu
 * @author ykk
 */
struct book_flow_node_port
{
  /** Constructor.
   * @param id_ id of node
   * @param port port number
   */
  book_flow_node_port(book_node id_, uint16_t port):
    id(id_)
  {
    this->port = port;
  }

  /** Node
   */
  book_node id;

  /** Node port
   */
  uint16_t port;
} __attribute__ ((packed));

/** \brief Structure to specify hop
 *
 * Copyright (C) Stanford University, 2009.
 * @date May 2009
 * @author dgu
 * @author ykk
 */
struct book_flow_hop
{
  /** Constructor.
   * @param src_port port number of input
   * @param id_ id of node
   * @param dst_port port number of output
   */
  book_flow_hop(uint16_t src_port,
		book_node id_, uint16_t dst_port):
    node_out(id_,dst_port)
  {
    this->src_port = src_port;
  }

  /** Source port
   */
  uint16_t src_port;
  /** Node and output port
   */
  book_flow_node_port node_out;
} __attribute__ ((packed));


/** \brief Structure to specify a flow,
 * for display of flows in the GUI.
 *
 * Copyright (C) Stanford University, 2009.
 * @date April 2009
 * @author dgu
 */
struct book_flow_spec
{
  /** Constructor.
   * @param num_hops  number of elements in the path
   * @param path      an array of hops
   */

  /** Flow type.
   */
  uint16_t type;
  /** Flow id.
   */
  uint32_t flow_id;
  /** Source node and its output port
   */
  book_flow_node_port src;
  /** Destination node and its input port
   */
  book_flow_node_port dst;

  /** Number of hops in the path
   * (excluding the source and destination)
   */
  uint16_t num_hops;
  /** Intermediate nodes
   */
  book_flow_hop path[0];
} __attribute__ ((packed));

/** \brief Body part of \ref book_message for
 * BOOKT_FLOWS_REQ messages.
 *
 * Copyright (C) Stanford University, 2009.
 * @date April 2009
 * @author ykk
 */
struct book_flow_req_message
{
  /** Type of request, from book_req_type
   */
  uint8_t type;
  /** Type of flow requested.
   */
  uint16_t flowType;
} __attribute__ ((packed));

/** \brief Body part of \ref book_message for
 * BOOKT_FLOWS_* messages.
 *
 * Copyright (C) Stanford University, 2009.
 * @date April 2009
 * @author dgu
 */
struct book_flow_message
{
  /** Number of flows in this message
   */
  uint32_t num_flows;

  /** Array of book_flow_spec
   */
  book_flow_spec body[0];
} __attribute__ ((packed));

/**************************************************
 * Stat proxy
 **************************************************/

/** \brief Body part of \ref book_message for
 * BOOKT_STAT_* messages.
 *
 * Copyright (C) Stanford University, 2008.
 * @date December 2008
 * @author ykk
 */
struct book_stat_message
{
  /** Switch datapath id.
   */
  uint64_t datapath_id;
  /** Type in ofp_stats_request.
   */
  uint16_t type;
  /** Flags as in ofp_stats_request.
   */
  uint16_t flags;
  /** Body of request as in ofp_stats_request/reply.
   */
  uint8_t osr_body[0];
} __attribute__ ((packed));


#endif
