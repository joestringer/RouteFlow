#include "sqlitelog.hh"
#include <boost/bind.hpp>
#include <iostream>

namespace vigil
{
  using namespace std;
  using namespace vigil::applications;

  static Vlog_module lg("sqlitelog");

  void sqlitelog::configure(const Configuration* config)
  {
    resolve(storage);
    running = false;

    timeval tim;
    tim.tv_sec = SQLITELOG_CHECK_INTERVAL;
    tim.tv_usec = 0;
    post(boost::bind(&sqlitelog::handle_check, this), tim);
  }

  void sqlitelog::install()
  { }

  void sqlitelog::handle_check()
  {
    VLOG_DBG(lg, "Checking sqlite log");
    if ((rowStore.size() >= SQLITELOG_THRESHOLD) && !running)
    {
      running = true;
      new sqlitelog_thread(this);
    }

    timeval tim;
    tim.tv_sec = SQLITELOG_CHECK_INTERVAL;
    tim.tv_usec = 0;
    post(boost::bind(&sqlitelog::handle_check, this), tim);
  }

  void sqlitelog::getInstance(const container::Context* ctxt,
				   sqlitelog*& ofp)
  {
    ofp = dynamic_cast<sqlitelog*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(sqlitelog).name())));
  }

  sqlitelog_thread::sqlitelog_thread(sqlitelog* log):
    sqllog(log)
  {
    start(boost::bind(&sqlitelog_thread::run, this));
  }

  sqlitelog_thread::~sqlitelog_thread()
  {}

  storage::Result sqlitelog::create_table(string TABLE, storage::Column_definition_map columns)
  {
    storage::Sync_transactional_storage store(storage);
    storage::Sync_transactional_storage::Get_connection_result result = store.get_connection();
    if (!result.get<0>().is_success())
      throw runtime_error("Can't access the transactional storage");
    storage::Sync_transactional_connection_ptr connection = result.get<1>();
    storage::Index_list indices;
    return connection->create_table(TABLE, columns, indices, 0);
  }

  void sqlitelog_thread::run()
  {
    list<pair<string,storage::Row> >::iterator i = sqllog->rowStore.begin();
    while (i != sqllog->rowStore.end())
    {
      storage::Sync_transactional_storage store(sqllog->storage);
      storage::Sync_transactional_storage::Get_connection_result result = store.get_connection();
      if (!result.get<0>().is_success())
	throw runtime_error("Can't access the transactional storage");
      storage::Sync_transactional_connection_ptr connection = result.get<1>();
      connection->put(i->first, i->second);
      i = sqllog->rowStore.erase(i);
    }
    sqllog->running = false;
  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::sqlitelog>,
		   vigil::sqlitelog);
