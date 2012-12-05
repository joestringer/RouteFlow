#include "flowdblogger.hh"
#include "netinet++/datapathid.hh"
#include "netinet++/ethernetaddr.hh"
#include <boost/bind.hpp>
#include "flow-removed.hh"
#include "assert.hh"
#include "openflow/openflow.h"
#include <sys/time.h>
#include "hash_map.hh"

namespace vigil
{
  using namespace std;
  using namespace vigil::container;
  using namespace vigil::applications;

  static Vlog_module lg("flowdblogger");

  void flowdblogger::configure(const Configuration* config)
  {
    resolve(sqllog);
    resolve(fdb);

    //Create table
    string TABLE = FLOWCOUNT_TABLENAME;
    storage::Column_definition_map ccolumns;
    ccolumns["TimeSec"] = (int64_t) 0;
    ccolumns["TimeUSec"] = (int64_t) 0;
    ccolumns["TotalFlow"] = (int64_t) 0;
    ccolumns["TotalUser"] = (int64_t) 0;
    ccolumns["CtrlFlow"] = (int64_t) 0;
    sqllog->create_table(TABLE, ccolumns);
    VLOG_DBG(lg, "Flow count database table created.");

    //Post periodic task.
    timeval tim;
    tim.tv_sec = FLOWCOUNT_CHECK_INTERVAL;
    tim.tv_usec = 0;
    post(boost::bind(&flowdblogger::periodic_check, this), tim);
  }

  void flowdblogger::periodic_check()
  {
    VLOG_DBG(lg, "Periodic database update.");

    size_t allsize = fdb->num_of_flows();
    size_t usersize = 0;
    size_t ctrlsize = 0;
    IPTable::iterator k = fdb->srcip_table.begin();
    while (k != fdb->srcip_table.end())
    {
      if((ntohl(k->first) > 0xAC1B4B0AUL) && (ntohl(k->first) < 0xAC1B4B47UL))
	usersize++;
      k++;
    }
    DB::iterator j = fdb->allFlow.begin();
    while (j != fdb->allFlow.end())
    {
      if ((((j->second->srcmac.hb_long() >= 0x000db9000000ULL) &&
	    (j->second->srcmac.hb_long() <= 0x000db9FFFFFFULL)) ||
	   ((j->second->srcmac.hb_long() >= 0x020db9000000ULL) &&
	    (j->second->srcmac.hb_long() <= 0x020db9FFFFFFULL))) &&
	  j->second->dstmac.hb_long() == 0x142209b9b0ULL)
	ctrlsize++;
      else if ((((j->second->dstmac.hb_long() >= 0x000db9000000ULL) &&
		 (j->second->dstmac.hb_long() <= 0x000db9FFFFFFULL)) ||
		((j->second->dstmac.hb_long() >= 0x020db9000000ULL) &&
		 (j->second->dstmac.hb_long() <= 0x020db9FFFFFFULL))) &&
	       j->second->srcmac.hb_long() == 0x142209b9b0ULL)
	ctrlsize++;
      j++;
    }

    timeval tim;
    gettimeofday(&tim, NULL);

    //Get connection
    string TABLE(FLOWCOUNT_TABLENAME);
    storage::Row row = *(new storage::Row());
    row["TimeSec"] = (int64_t) tim.tv_sec;
    row["TimeUSec"] = (int64_t) tim.tv_usec;
    row["TotalFlow"]= (int64_t) allsize;
    row["TotalUser"]= (int64_t) usersize;
    row["CtrlFlow"] = (int64_t) ctrlsize;
    sqllog->rowStore.push_back(std::make_pair(TABLE, row));
    VLOG_DBG(lg, "Size of sql log %zu", sqllog->rowStore.size());

    //Post periodic task.
    tim.tv_sec = FLOWCOUNT_CHECK_INTERVAL;
    tim.tv_usec = 0;
    post(boost::bind(&flowdblogger::periodic_check, this), tim);
  }

  void flowdblogger::getInstance(const container::Context* ctxt,
				 flowdblogger*& ofp)
  {
    ofp = dynamic_cast<flowdblogger*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(flowdblogger).name())));
  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::flowdblogger>,
		   vigil::flowdblogger);
