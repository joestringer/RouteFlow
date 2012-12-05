#include "timcanpy.hh"
#include "assert.hh"
#include <boost/bind.hpp>
#include <boost/shared_array.hpp>
#include "openflow-msg-in.hh"
#include <iostream>
#include <fstream>

namespace vigil
{
  static Vlog_module lg("timcanpy");

  void timcanpy::configure(const Configuration* config)
  {
    resolve(ofp);
    resolve(book);

    register_handler<Openflow_msg_event>
      (boost::bind(&timcanpy::handle_of_msg_in, this, _1));

    //Read dpid hostname file
    std::ifstream ifs(DPID_HOSTNAME_FILE);
    char dpidString[20];
    char hostString[100];

    while (ifs)
    {
      ifs.getline(hostString, 100);
      ifs.getline(dpidString, 20);
      uint64_t dpid = strtoull(dpidString,NULL,16);
      dpidhostlist.insert(std::make_pair(dpid,std::string(hostString)));
    }
  }

  void timcanpy::getInstance(const container::Context* ctxt,
			      timcanpy*& ofp)
  {
    ofp = dynamic_cast<timcanpy*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(timcanpy).name())));
  }

  void timcanpy::handle_stat_req(const Book_msg_event& bm)
  {
    //Add to request map for tracking
    requestMap.insert(std::make_pair(bm.msg->header.xid,new Msg_stream(*bm.sock)));

    //Send request to OpenFlow switch
    book_stat_message* bsm = (book_stat_message*) bm.msg->body;
    ssize_t size = ntohs(bm.msg->header.length)-sizeof(book_header)-\
      sizeof(book_stat_message)+sizeof(ofp_stats_request);
    ofp->init(of_raw, size, OFPT_STATS_REQUEST, ntohl(bm.msg->header.xid));
    ofp_stats_request* osr = (ofp_stats_request*) of_raw.get();

    osr->type = bsm->type;
    osr->flags = bsm->flags;
    memcpy(osr->body, bsm->osr_body, size-sizeof(ofp_stats_request));
    ofp->send_command(of_raw, datapathid::from_net(bsm->datapath_id), false);
    VLOG_DBG(lg, "Sent OpenFlow stat request with xid %"PRIx32"",
	     ntohl(bm.msg->header.xid));
  }

  Disposition timcanpy::handle_of_msg_in(const Event& e)
  {
    const Openflow_msg_event& ome = assert_cast<const Openflow_msg_event&>(e);

    if (ome.get_ofp_msg()->type == OFPT_STATS_REPLY)
    {
      ofp_stats_reply* osr = (ofp_stats_reply*)ome.get_ofp_msg();
      VLOG_DBG(lg, "Received OpenFlow stat reply with xid %"PRIx32"",
	       ntohl(osr->header.xid));

      //Mod description
      if (osr->type == OFPST_DESC)
      {
	ofp_desc_stats* ods = (ofp_desc_stats*) osr->body;
	hash_map<uint64_t,std::string>::iterator mapi = dpidhostlist.find(ome.datapath_id.as_host());
	if (mapi != dpidhostlist.end())
	  strcpy(ods->hw_desc, mapi->second.c_str());
      }

      hash_map<uint32_t, Msg_stream*>::iterator i =
	requestMap.find(osr->header.xid);
      while (i != requestMap.end())
      {
	book->stat_reply(ome,i->second);
	VLOG_DBG(lg, "Stat reply proxied for %"PRIx64" of xid %"PRIx32"",
		 ome.datapath_id.as_host(),
		 ntohl(osr->header.xid));
	requestMap.erase(i);
	i = requestMap.find(osr->header.xid);
      }
    }
    return CONTINUE;
  }

  void timcanpy::clearConnection(const Book_msg_event& bm)
  {
    VLOG_DBG(lg, "Clearing state of connection");

    //Remove requests sent
    hash_map<uint32_t, Msg_stream*>::iterator i = requestMap.begin();
    while (i != requestMap.end())
      if(&(*(i->second->stream)) == &(*(bm.sock->stream)))
      {
	i=requestMap.erase(i);
	VLOG_DBG(lg, "Removed request due to connection close ");
      }
      else
	i++;
  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::timcanpy>,
		   vigil::timcanpy);
