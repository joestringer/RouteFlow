#include "assert.hh"
#include "circsw_gui.hh"
#include "circsw_config.hh"

namespace vigil
{
  using namespace std;

  static Vlog_module lg("circsw");
  // int c = 0;
  // Msg_stream* sock = NULL;


  L1_flow_drag_event::L1_flow_drag_event(uint32_t flowid_, std::vector<uint64_t> dpids_):
    Event(static_get_name()) {
    dpids = dpids_;
    flowid = flowid_;

    VLOG_DBG(lg, "L1_flow_drag_event with flowid %"PRId32" ############", flowid);
    for (int i= 0; i < dpids.size(); i++ ) {
      VLOG_DBG(lg, "Waypoint dpid: %"PRIx64"", dpids[i]);
    }
  }


  void
  Circsw_gui::configure(const Configuration* config) {
    resolve(golem);
    resolve(book);

    congestion_count = 0;
    flash_on = false;

    register_event(L1_flow_drag_event::static_get_name());

    register_handler<Book_msg_event>
      (boost::bind(&Circsw_gui::handle_message, this, _1));
  }

  void
  Circsw_gui::registerNodes( uint16_t nodetype, uint64_t datapathid ) {

    //ciena3  = new booknode(BOOKN_CIENA_SWITCH, 0x08709727);
    //nodes.push_front( *ciena3 );
    if ( searchnodes.find( datapathid ) == searchnodes.end() ) {
      booknode* node = new booknode( nodetype, datapathid );
      nodes.push_front( *node );
      searchnodes.insert( std::make_pair( datapathid, node ) );
      for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
            iter != guiClients.end(); ++iter ) {
        VLOG_DBG(lg, "Sending nodes list(%d) to GUI client Msg_stream %"PRIx32"",
                 nodes.size(), *((int*)*iter));
        book->send_node_listd( nodes, *iter, true);
      }
    }

  }

  void
  Circsw_gui::registerLinks( uint16_t linktype, uint64_t dpid1, uint16_t port1,
                             uint64_t dpid2, uint16_t port2, uint16_t linkid ) {
    if ( searchlinks.find( linkid ) == searchlinks.end() ) {
      booklinkspec* link = new booklinkspec( linktype, *searchnodes[dpid1], port1,
                                             *searchnodes[dpid2], port2 );
      //booklinkspec* link = new booklinkspec( linktype, *searchnodes[dpid1], port1,
      //                                       *ciena3, port2 );

      links.push_front( *link );
      searchlinks.insert( std::make_pair( linkid, link ) );
      for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
            iter != guiClients.end(); ++iter ) {
        VLOG_DBG(lg, "Sending links list(%d) to GUI client Msg_stream %"PRIx32"",
                 links.size(), *((int*)*iter));
        book->send_link_list( links, *iter, true);
      }
    }

  }


  Disposition
  Circsw_gui::handle_message(const Event& e){
    const Book_msg_event& bme = assert_cast<const Book_msg_event&>(e);
    flow_drag_req* fdr;
    uint64_t* fdr_dpid;
    int waypt_no;
    struct book_stat_message* bsm;
    //sock = new Msg_stream(*bme.sock);
    std::vector<uint64_t> dpids;

    switch(bme.msg->header.type)
      {
      case BOOKT_CKT_NODES_REQ:
        handle_flow_subscribe(bme);
        for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
              iter != guiClients.end(); ++iter ) {
          book->send_node_listd( nodes, *iter, true);
        }
        //book->send_node_list(nodes, bme.sock, true);
        VLOG_DBG(lg, "Got a ckt nodes request");
        return STOP;
        //break;

      case BOOKT_NODES_REQ:
        VLOG_DBG(lg, "ignoring a nodes request");
        break;

      case BOOKT_CKT_LINKS_REQ:
        for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
              iter != guiClients.end(); ++iter ) {
          book->send_link_list( links, *iter, true);
        }
        //book->send_link_list(links, bme.sock, true);
        VLOG_DBG(lg, "Got a ckt links request");
        return STOP;
        //break;

      case BOOKT_LINKS_REQ:
        VLOG_DBG(lg, "ignoring a links request");
        break;


      case BOOKT_CKT_FLOWS_REQ:
        VLOG_DBG(lg, "Got a ckt flows request");
        for (std::map<uint32_t, flow_entry>::iterator iter =    \
               flowdb.begin(); iter != flowdb.end(); ++iter ) {
          for (std::list<single_routed>::iterator i = iter->second.routelist.begin();
               i != iter->second.routelist.end(); i++) {
            for (std::list<Route_hopd>::iterator j = i->begin();
                 j != i->end(); j++) {
              VLOG_DBG( lg, "Hop: inp=%"PRIx16" sw=%"PRIx64" out=%"PRIx16"", \
                        j->in_port, j->sw.as_host(), j->out_port );

            }
          }
          for ( std::list<Msg_stream*>::iterator iter2 = guiClients.begin();
                iter2 != guiClients.end(); ++iter2 ) {
            book->send_flow_listd( iter->second.routelist, *iter2, true,
                                   iter->first, iter->second.flowtype );
          }
        }
        return STOP;
        //break;

      case BOOKT_FLOWS_REQ:
        VLOG_DBG(lg, "ignoring a flows request");
        break;


      case BOOKT_POLL:
        /*
        //XXX hack
        if (++c == 60) {
        dpids.push_back(UINT64_C(0x0000b56002ebd000));
        dpids.push_back(UINT64_C(0x0000af9e02ebd000));
        //  dpids.push_back(UINT64_C(0x0000a1d002ebd000));
        post(new L1_flow_drag_event( 2 , dpids));
        }
        //end hack
        */
        break;

      case BOOKT_DRAG_REQ:

        fdr = (flow_drag_req*) bme.msg;
        waypt_no = ( ntohs(fdr->header.length) - sizeof(flow_drag_req) )/8;
        fdr_dpid = fdr->waypoint_dpid;
        for (int k = 0; k < waypt_no; k++)
          {
            VLOG_DBG(lg, "%"PRIx64"", ntohll(*fdr_dpid));
            dpids.push_back(ntohll(*fdr_dpid));
            fdr_dpid++;

          }
        VLOG_DBG(lg, "num dpids:%d flowid:%d ", waypt_no, ntohl(fdr->flow_id)/256 );
        post(new L1_flow_drag_event( ntohl(fdr->flow_id)/256, dpids));
        dpids.clear();
        //break;
        return STOP;

      case BOOKT_DISCONNECT:
        flow_unsubscribe(bme);
        break;

      case BOOKT_STAT_REQ:
        bsm = (book_stat_message*) bme.msg->body;
        if ( searchnodes.find( ntohll(bsm->datapath_id) ) != searchnodes.end() ) {
          VLOG_DBG( lg, " Stat req for ckt node:%"PRIx64" ... ignoring ",
                    ntohll(bsm->datapath_id) );
          return STOP;
        }

        VLOG_DBG( lg, " Stat req for node:%"PRIx64" .. passing it on",
                  ntohll(bsm->datapath_id) );
        break;

      default:
        VLOG_WARN( lg, "*** Unkown Book_msg_event type: 0x%x", bme.msg->header.type );

      }

    return CONTINUE;
  }


  void
  Circsw_gui::handle_flow_subscribe(const Book_msg_event& bme) {
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
  Circsw_gui::flow_subscribe(const Book_msg_event& bme) {
    for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
          iter != guiClients.end(); ++iter ) {
      if ( *iter == bme.sock ) return;
    }
    guiClients.push_back( new Msg_stream(*bme.sock) );
    VLOG_DBG(lg, "New GUI client msg_Stream %"PRIx32"",*((int*)bme.sock) );
  }

  void
  Circsw_gui::flow_unsubscribe(const Book_msg_event& bme) {
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
  Circsw_gui::addAFlow( std::list<single_routed> routes, uint32_t flow_id,
                      uint16_t flowtype ) {
    VLOG_DBG( lg, "----ADDING A GUI FLOW id:%d type:%d----",
              flow_id, flowtype);

    for (std::list<single_routed>::iterator i = routes.begin();
         i != routes.end(); i++) {
      for (std::list<Route_hopd>::iterator j = i->begin();
           j != i->end(); j++) {
        VLOG_DBG( lg, "Hop: inp=%"PRIx16" sw=%"PRIx64" out=%"PRIx16"", \
                  j->in_port, j->sw.as_host(), j->out_port );
      }
    }
    flow_entry fe;
    fe.flowtype = flowtype;
    fe.routelist = routes;
    flowdb.insert( std::make_pair( flow_id, fe ) ); //XXX overwriting same flowid
    //if( sock )
    for ( std::list<Msg_stream*>::iterator iter = guiClients.begin();
          iter != guiClients.end(); ++iter ) {
      VLOG_DBG(lg, "Sending flows listd(%d) to GUI client Msg_stream %"PRIx32"",
               routes.size(), *((int*)*iter));

      book->send_flow_listd( routes, *iter, true, flow_id, flowtype);
    }
  }

  void
  Circsw_gui::getInstance(const container::Context* ctxt, Circsw_gui*& ofp){
    ofp = dynamic_cast<Circsw_gui*>(ctxt->get_by_interface                \
                                  (container::Interface_description     \
                                   (typeid(Circsw_gui).name())));
  }

  void
  Circsw_gui::removeAllFlows( void ) {
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

  void
  Circsw_gui::removeAFlow( uint32_t flow_id, bool sendtempflow ) {
    std::map<uint32_t, flow_entry>::iterator iter = flowdb.find( flow_id );
    if ( iter != flowdb.end() ) {
      VLOG_DBG( lg, "Deleting gui flow with flow_id %d", iter->first );
      // if( sock )
      for ( std::list<Msg_stream*>::iterator iter2 = guiClients.begin();
            iter2 != guiClients.end(); ++iter2 ) {
        book->send_flow_listd( iter->second.routelist, *iter2, false, \
                               iter->first, iter->second.flowtype );
        if ( sendtempflow ) {
          book->send_flow_listd( iter->second.routelist, *iter2, true, \
                               iter->first, BOOKF_TEMP );
        }
      }
      if ( !sendtempflow ) flowdb.erase( iter );
    }
  }

  void
  Circsw_gui::showCongestion( void ) {
    ++congestion_count;
    for ( std::list<Msg_stream*>::iterator iter2 = guiClients.begin();
          iter2 != guiClients.end(); ++iter2 ) {
      if( congestion_count%2 ) {
        book->send_node_list(tempnode, *iter2, true);
        flash_on = true;
      } else {
        book->send_node_list(tempnode, *iter2, false);
        flash_on = false;
      }
    }
  }

  void
  Circsw_gui::showNoCongestion( void ) {
    if ( flash_on ) {
      for ( std::list<Msg_stream*>::iterator iter2 = guiClients.begin();
            iter2 != guiClients.end(); ++iter2 ) {
        book->send_node_list(tempnode, *iter2, false);
        flash_on = false;
      }
    }
  }



}

REGISTER_COMPONENT(vigil::container::Simple_component_factory
                   <vigil::Circsw_gui>,
                   vigil::Circsw_gui);
