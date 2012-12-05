#include "assert.hh"
#include "mpls_gui.hh"
#include "mpls_config.hh"


namespace vigil
{
  using namespace std;

  static Vlog_module lg("mpls_gui");

  void
  Mpls_gui::configure(const Configuration* config) {
    resolve(golem);
    resolve(book);

    register_handler<Book_msg_event>
      (boost::bind(&Mpls_gui::handle_message, this, _1));
  }


  Disposition
  Mpls_gui::handle_message(const Event& e){
    const Book_msg_event& bme = assert_cast<const Book_msg_event&>(e);
    std::vector<uint64_t> dpids;

    switch(bme.msg->header.type)
      {
      case BOOKT_FLOWS_REQ:
        handle_flow_subscribe(bme);
        // Not creating a separate tunnel subscription.
        // So a BOOKT_FLOWS_REQ will subscribe the GUI for both flows and tunnels.
        sendAllTunnels();
        sendAllFlows();

        // Need to prevent lavi components from doing anything
        return STOP;
        //break;


      case BOOKT_POLL:
        VLOG_DBG(lg, "ignoring a poll request");
        break;

      case BOOKT_DISCONNECT:
        flow_unsubscribe(bme);
        break;

      default:
        if (bme.msg->header.type < 0x50) {
          VLOG_WARN( lg, "*** Unkown Book_msg_event type: 0x%x",
                     bme.msg->header.type );
        }
      }

    return CONTINUE;
  }


  void
  Mpls_gui::handle_flow_subscribe(const Book_msg_event& bme) {
	book_flow_req_message* value = (book_flow_req_message*) bme.msg->body;
	if(value->type == BOOKR_ONETIME){
	  VLOG_DBG(lg,"onetime requests for flows are not handled");
	}
	else if(value->type == BOOKR_SUBSCRIBE){
	  flow_subscribe(bme);
	}
	else if(value->type == BOOKR_UNSUBSCRIBE){
	  flow_unsubscribe(bme);
	}
  }

  void
  Mpls_gui::flow_subscribe(const Book_msg_event& bme) {
    for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
          iter != guiClients.end(); ++iter ) {
      if ( *iter == bme.sock ) return;
    }
    guiClients.push_back( new Msg_stream(*bme.sock) );
    VLOG_DBG(lg, "New GUI client msg_Stream %"PRIx32"",*((int*)bme.sock) );
  }

  void
  Mpls_gui::flow_unsubscribe(const Book_msg_event& bme) {
   for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
          iter != guiClients.end(); ++iter ) {
     if ( *iter == bme.sock ) {
       guiClients.erase( iter );
       VLOG_DBG(lg, "GUI client sock %"PRIx32" disconnected", *((int*)bme.sock) );
       return;
     }
   }
  }


  void
  Mpls_gui::addFlow( uint32_t flow_id, const Routing_module::Route& route,
                     uint16_t inport, uint16_t outport, uint16_t flowtype) {
    //need to convert from routing flow to gui flow
    single_route sr;
    datapathid nxtdpid;
    uint16_t nxtinport = inport;
    for( std::list<Routing_module::Link>::const_iterator iter = route.path.begin();
         iter != route.path.end(); ++iter ) {
      if( iter == route.path.begin() ) {
        struct Route_hop src( inport, route.id.src,  iter->outport );
        sr.push_back( src );
        nxtdpid = iter->dst;
        nxtinport = iter->inport;
        continue;
      }
      struct Route_hop intermediate( nxtinport, nxtdpid, iter->outport );
      sr.push_back( intermediate );
      nxtdpid = iter->dst;
      nxtinport = iter->inport;
    }
    struct Route_hop dst( nxtinport, nxtdpid, outport );
    sr.push_back( dst );

    std::list<single_route> thisroute;
    thisroute.push_back( sr );

    // sanity check
    VLOG_DBG( lg, "----ADDING A GUI FLOW id:%"PRIx32" type:%x----",
              flow_id, flowtype);
    for (std::list<single_route>::iterator i = thisroute.begin();
         i != thisroute.end(); i++) {
      for (std::list<Route_hop>::iterator j = i->begin();
           j != i->end(); j++) {
        VLOG_DBG( lg, "Hop: inp=%"PRIx16" sw=%"PRIx64" out=%"PRIx16"", \
                  j->in_port, j->sw.as_host(), j->out_port );
      }
    }

    // enter into flowdb for GUI
    flow_entry fe;
    fe.flowtype = flowtype;
    fe.routelist = thisroute;
    flowdb.insert( std::make_pair( flow_id, fe ) );

    // send to all GUIs
    for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
          iter != guiClients.end(); ++iter ) {
      VLOG_DBG(lg, "Sending flows list(%d) to GUI client Msg_stream %"PRIx32"",
               thisroute.size(), *((int*)*iter));
      book->send_flow_list( thisroute, *iter, true, flow_id, flowtype);
    }
  }


  void
  Mpls_gui::delFlow( uint32_t flow_id ) {
    flow_entry& fe = flowdb[flow_id];
    // send to all GUIs
    for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
          iter != guiClients.end(); ++iter ) {
      VLOG_DBG(lg, "Sending DEL flows list(%d) to GUI client Msg_stream %"PRIx32"",
               fe.routelist.size(), *((int*)*iter));
      book->send_flow_list( fe.routelist, *iter, false, flow_id, fe.flowtype);
    }
    flowdb.erase( flow_id );
  }

  void
  Mpls_gui::sendAllFlows( void ) {
    for (std::map<uint32_t, flow_entry>::iterator iter = flowdb.begin();
         iter != flowdb.end(); ++iter ) {
      for ( std::list<Msg_stream*>::iterator iter2 = guiClients.begin();
            iter2 != guiClients.end(); ++iter2 ) {
        book->send_flow_list( iter->second.routelist, *iter2, true,
                              iter->first, iter->second.flowtype );
      }
    }
  }




/*
  void
  Mpls_gui::removeAllFlows( void ) {
    for (std::map<uint32_t, flow_entry >::iterator iter = \
           flowdb.begin(); iter != flowdb.end(); ++iter ) {
      VLOG_DBG( lg, "Deleting gui flow with flow_id %d", iter->first );
      //if( sock )
      for ( std::list<Msg_stream*>::iterator iter2 = guiClients.begin();
            iter2 != guiClients.end(); ++iter2 ) {
        book->send_flow_listd( iter->second.routelist, *iter2, false, \
                               iter->first, iter->second.flowtype );
      }
    }
    flowdb.clear();
  }


*/


  void
  Mpls_gui::addTunnel( uint16_t tid, uint8_t color, uint8_t prio,
                       uint32_t resbw, bool autobw, uint8_t trtype,
                       std::list<uint64_t>& dplist ) {
    tunnel_entry te;
    te.tid = htons(tid);
    te.color = color;
    te.priority  = prio;
    te.current_resbw = htonl(resbw);
    te.usage = 0;
    te.autobw = (autobw)? 1 : 0;
    te.trtype = trtype;
    te.hoplist = dplist;
    tunneldb.insert( std::make_pair(tid, te) );
    for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
          iter != guiClients.end(); ++iter ) {
      VLOG_DBG(lg, "Sending tunnel list(size:%d) to GUI client Msg_stream %"PRIx32"",
               te.hoplist.size(), *((int*)*iter));
      send_tunnel( tid, *iter);
    }

  }

    void
  Mpls_gui::removeTunnel( uint16_t tid) {
   /*ssize_t size = sizeof(book_header) + sizeof(mpls_tunnel_reply_message);
    golem->init(rawmsg, size, BOOKT_MPLS_TUNN_REPLY);
    mpls_tunnel_reply_message* mtr = (mpls_tunnel_reply_message*) \
        ((book_message*) rawmsg.get())->body;
    mtr->del = 1;
    mtr->tid = htons(tid);
    */
    ssize_t size = sizeof(book_header) + sizeof(mpls_tunnel_reply_message) +
                   tunneldb[tid].hoplist.size() * sizeof(mpls_tunnel_hop);
    golem->init(rawmsg, size, BOOKT_MPLS_TUNN_REPLY);
    tunnel_entry& te = tunneldb[tid];
    mpls_tunnel_reply_message* mtr = (mpls_tunnel_reply_message*) \
      ((book_message*) rawmsg.get())->body;
    mtr->del = 1;
    mtr->tid = te.tid;
    mtr->color = te.color;
    mtr->priority = te.priority;
    mtr->resbw = te.current_resbw;
    mtr->usage = te.usage;
    mtr->autobw = te.autobw;
    mtr->trtype = te.trtype;
    mtr->num_hops = htons((uint16_t) te.hoplist.size());
    // add each hop from hoplist which is already in net.b.o.
    mpls_tunnel_hop* h = (mpls_tunnel_hop*)mtr->path;
    for( std::list<uint64_t>::iterator iter = te.hoplist.begin();
         iter != te.hoplist.end(); ++iter ) {
      h->hopdpid = *iter;
      h++;
    }

    for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
        iter != guiClients.end(); ++iter ) {
        golem->send(rawmsg, (*iter)->stream);
    }

  }


  void
  Mpls_gui::send_tunnel( uint16_t tid, Msg_stream* sock, uint8_t del ) {
    ssize_t size = sizeof(book_header) + sizeof(mpls_tunnel_reply_message) +
                   tunneldb[tid].hoplist.size() * sizeof(mpls_tunnel_hop);
    golem->init(rawmsg, size, BOOKT_MPLS_TUNN_REPLY);
    tunnel_entry& te = tunneldb[tid];
    mpls_tunnel_reply_message* mtr = (mpls_tunnel_reply_message*) \
      ((book_message*) rawmsg.get())->body;
    mtr->del = del;
    mtr->tid = te.tid;
    mtr->color = te.color;
    mtr->priority = te.priority;
    mtr->resbw = te.current_resbw;
    mtr->usage = te.usage;
    mtr->autobw = te.autobw;
    mtr->trtype = te.trtype;
    mtr->num_hops = htons((uint16_t) te.hoplist.size());
    // add each hop from hoplist which is already in net.b.o.
    mpls_tunnel_hop* h = (mpls_tunnel_hop*)mtr->path;
    for( std::list<uint64_t>::iterator iter = te.hoplist.begin();
         iter != te.hoplist.end(); ++iter ) {
      h->hopdpid = *iter;
      h++;
    }

    golem->send(rawmsg, sock->stream);

  }

  void
  Mpls_gui::sendTunnelStats( uint16_t tid, uint32_t bw, uint32_t usage, int32_t change ) {
    ssize_t size = sizeof(book_header) + sizeof(mpls_tunnel_stats_message) +
                   tunneldb[tid].hoplist.size() * sizeof(mpls_tunnel_hop);
    golem->init(rawmsg, size, BOOKT_MPLS_STATS);
    tunnel_entry& te = tunneldb[tid];
    mpls_tunnel_stats_message* mts = (mpls_tunnel_stats_message*) \
      ((book_message*) rawmsg.get())->body;
    mts->tid = te.tid;
    mts->curr_resbw = te.current_resbw = htonl(bw);
    mts->usage = te.usage = htonl(usage);
    mts->change = htonl(change);
    mts->num_hops = htons((uint16_t) te.hoplist.size());
    // add each hop from hoplist which is already in net.b.o.
    mpls_tunnel_hop* h = (mpls_tunnel_hop*)mts->path;
    for( std::list<uint64_t>::iterator iter = te.hoplist.begin();
         iter != te.hoplist.end(); ++iter ) {
      h->hopdpid = *iter;
      h++;
    }

    for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
          iter != guiClients.end(); ++iter ) {
      golem->send(rawmsg, (*iter)->stream);
    }
  }


  void
  Mpls_gui::sendAllTunnels( void ) {
    for( std::map<uint16_t, tunnel_entry>::iterator iter = tunneldb.begin();
         iter != tunneldb.end(); ++iter ) {
      for ( std::list<Msg_stream*>::iterator iter1 = guiClients.begin();
            iter1 != guiClients.end(); ++iter1 ) {
        send_tunnel( iter->first, *iter1 );
      }
    }
  }

  void
  Mpls_gui::getInstance(const container::Context* ctxt, Mpls_gui*& ofp){
    ofp = dynamic_cast<Mpls_gui*>(ctxt->get_by_interface                \
                                  (container::Interface_description     \
                                   (typeid(Mpls_gui).name())));
  }

}

REGISTER_COMPONENT(vigil::container::Simple_component_factory
                   <vigil::Mpls_gui>,
                   vigil::Mpls_gui);
