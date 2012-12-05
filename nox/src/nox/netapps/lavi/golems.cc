#include "golems.hh"
#include "bookman-msg-event.hh"
#include "vlog.hh"
#include <sstream>
#include <boost/foreach.hpp>

namespace vigil
{
  using namespace vigil::container;

  static Vlog_module lg("golems");
  static const std::string app_name("golems");

  golems::golems(const Context* c, const xercesc::DOMNode* node):
    message_processor(c,node)
  {
    lastxid = 0;
    idleInterval = 10;
    thresholdEchoMissed = 3;
  };

  void golems::configure(const Configuration* config)
  {
    resolve(msg_core);
    resolve(msger);

    register_event(Book_msg_event::static_get_name());

    //Get default port configuration
    if (ENABLE_TCP_GOLEMS)
      tcpport = GOLEMS_PORT;
    else
      tcpport = 0;
    if (ENABLE_SSL_GOLEMS)
      sslport = GOLEMS_SSL_PORT;
    else
      sslport = 0;

    //Get commandline arguments
    BOOST_FOREACH (const std::string& arg_str, config->get_arguments())
    {
      //Get each argument
      std::stringstream args(arg_str);
      std::string arg;
      int argcount = 0;
      while (getline(args, arg, ','))
      {
	//Look into each argument
        std::stringstream argsplit(arg);
        std::string argid, argval, tmparg;
	while (getline(argsplit, tmparg, '='))
	{
	  switch (argcount)
	  {
	  case 0:
	    argid=tmparg;
	    break;
	  case 1:
	    argval=tmparg;
	    break;
	  default:
	    VLOG_WARN(lg, "Peculiar argument %s", arg.c_str());
	  }
	  argcount++;
	}
	//Check for known arguments
	if (argid == "tcpport")
	  tcpport = (uint16_t) atoi(argval.c_str());
	else if (argid == "sslport")
	  sslport = (uint16_t) atoi(argval.c_str());
	else
	  VLOG_WARN(lg, "Unknown argument %s = %s",
		   argid.c_str(), argval.c_str());
      }
    }
  }

  void golems::install()
  {
    if (tcpport != 0)
      msg_core->start_tcp(this, tcpport);

    if (sslport != 0)
    {
      boost::shared_ptr<Ssl_config>
	config(new Ssl_config(Ssl_config::ALL_VERSIONS,
			      Ssl_config::NO_SERVER_AUTH,
			      Ssl_config::NO_CLIENT_AUTH,
			      "nox/netapps/lavi/serverkey.pem",
			      "nox/netapps/lavi/servercert.pem",
			      "nox/netapps/lavi/cacert.pem"));
      msg_core->start_ssl(this, sslport, config);    }
  }


  void golems::init(boost::shared_array<uint8_t>& msg_raw, ssize_t size,
		    uint8_t type, uint32_t xid)
  {
    msger->init(msg_raw, size, type);
    book_message* bookmsg = (book_message*) msg_raw.get();
    bookmsg->header.xid = htonl(xid);
  }

  void golems::init(boost::shared_array<uint8_t>& msg_raw, ssize_t size, uint8_t type)
  {
    init(msg_raw, size, type, nextxid());
  }

  void golems::send_echo(Async_stream* sock)
  {
    //VLOG_DBG(lg, "Sending echo on idle socket");
    init(raw_book, sizeof(book_message), BOOKT_ECHO);
    send(raw_book, sock);
  }

  void golems::send(boost::shared_array<uint8_t>& msg, Async_stream* sock)
  {
    msger->send(msg,sock);
  }

  void golems::getInstance(const container::Context* ctxt,
			   vigil::golems*& scpa)
  {
    scpa = dynamic_cast<golems*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(golems).name())));
  }

  void golems::process(const Msg_event* msg)
  {
    //VLOG_DBG(lg, "Message posted as Book_msg_event");
    post(new Book_msg_event((book_message*)msg->msg,
			    msg->sock->stream,
			    msg->sock->isSSL));
  }
}

namespace noxsup
{
  REGISTER_COMPONENT(vigil::container::
		     Simple_component_factory<vigil::golems>,
		     vigil::golems);
}
