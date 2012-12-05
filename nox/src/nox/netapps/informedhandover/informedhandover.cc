#include "informedhandover.hh"

namespace vigil
{
  static Vlog_module lg("informedhandover");

  void informedhandover::getInstance(const container::Context* ctxt,
				   informedhandover*& ofp)
  {
    ofp = dynamic_cast<informedhandover*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(informedhandover).name())));
  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::informedhandover>,
		   vigil::informedhandover);
