/* Copyright 2008 (C) Stanford University.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OPENFLOW_MSG_HH__
#define OPENFLOW_MSG_HH__

#include <string>
#include "event.hh"
#include "netinet++/datapathid.hh"
#include "ofp-msg-event.hh"

#include "openflow/openflow.h"

namespace vigil {

struct Openflow_msg_event
    : public Event,
      public Ofp_msg_event
{
    Openflow_msg_event(const datapathid& dpid, const ofp_header* ofp_msg_,
		       std::auto_ptr<Buffer> buf);

    // -- only for use within python
    Openflow_msg_event() : Event(static_get_name()) { }

    static const Event_name static_get_name() {
        return "Openflow_msg_event";
    }

    datapathid datapath_id;
}; 

inline
Openflow_msg_event::Openflow_msg_event(const datapathid& dpid, const ofp_header* ofp_msg_,
				       std::auto_ptr<Buffer> buf)
  : Event(static_get_name()), Ofp_msg_event(ofp_msg_, buf)
{
    datapath_id = dpid;
}

} // namespace vigil

#endif
