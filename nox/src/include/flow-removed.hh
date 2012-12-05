/* Copyright 2008, 2009 (C) Nicira, Inc.
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
#ifndef FLOW_REMOVED_HH
#define FLOW_REMOVED_HH 1

#include <boost/noncopyable.hpp>
#include "event.hh"
#include "flow-event.hh"
#include "ofp-msg-event.hh"
#include "xtoxll.h"

namespace vigil {

/** \ingroup noxevents
 *
 * Flow removed events are thrown for each OpenFlow Flow Removed 
 * message received by the controller.  Flow Removed messages are sent 
 * by the switches on flow timeout (either hard or soft) or explicit
 * flow deletion.  Flow Removed messages are only generated by switches 
 * if they are told to do so by the controller (Flow Removed messages 
 * are <b>not</b> enabled in NOX by default).
 *
 */

struct Flow_removed_event
    : public Event,
      public Ofp_msg_event,
      public Flow_event,
      boost::noncopyable
{
    Flow_removed_event(datapathid datapath_id_,
                       uint16_t priority_, uint8_t reason_,
                       uint32_t duration_sec_, uint32_t duration_nsec_,
		       uint16_t idle_timeout_,
                       uint64_t packet_count_, uint64_t byte_count_,
		       uint64_t cookie_)
        : Event(static_get_name()), datapath_id(datapath_id_),
          priority(priority_), reason(reason_),
          duration_sec(duration_sec_), duration_nsec(duration_nsec_),
	  idle_timeout(idle_timeout_),
          packet_count(packet_count_), byte_count(byte_count_),
          cookie(cookie_) { }


    Flow_removed_event(const datapathid datapath_id_, 
                       const ofp_flow_removed *ofr,
                       std::auto_ptr<Buffer> buf);

    // -- only for use within python
    Flow_removed_event() : Event(static_get_name()) { ; }

    //! ID of switch sending the Flow Removed message 
    datapathid datapath_id;
  // reason and priority
  uint16_t priority;
  uint8_t reason;

    //! Duration of the flow in seconds and nanoseconds
    uint32_t duration_sec;
    uint32_t duration_nsec;
    //! Idle timeout from original flow mod.
    uint16_t idle_timeout;
    uint64_t packet_count;
    uint64_t byte_count;
    //Opaque cookie
    uint64_t cookie;

    const ofp_match* get_flow() const {
        return &get_flow_removed()->match;
    }

    const ofp_flow_removed* get_flow_removed() const {
        return reinterpret_cast<const ofp_flow_removed*>(get_ofp_msg());
    }

    static const Event_name static_get_name() {
        return "Flow_removed_event";
    }
};

inline
Flow_removed_event::Flow_removed_event(datapathid datapath_id_,
                                       const ofp_flow_removed *ofr,
                                       std::auto_ptr<Buffer> buf)
    : Event(static_get_name()), Ofp_msg_event(&ofr->header, buf),
      datapath_id(datapath_id_)
{
  reason  = ofr->reason;
  priority = ntohs(ofr->priority);
    cookie  = ntohll(ofr->cookie);
    duration_sec  = ntohl(ofr->duration_sec);
    duration_nsec = ntohl(ofr->duration_nsec);
    idle_timeout  = ntohs(ofr->idle_timeout);
    packet_count  = ntohll(ofr->packet_count);
    byte_count    = ntohll(ofr->byte_count);
}

} // namespace vigil

#endif /* flow-removed.hh */
