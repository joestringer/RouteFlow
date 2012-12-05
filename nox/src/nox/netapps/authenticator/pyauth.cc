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
#include "pyauth.hh"

#include "swigpyrun.h"
#include "pyrt/pycontext.hh"

namespace vigil {
namespace applications {

PyAuthenticator::PyAuthenticator(PyObject* ctxt)
    : authenticator(0)
{
    SwigPyObject* swigo = SWIG_Python_GetSwigThis(ctxt);
    if (!swigo || !swigo->ptr) {
        throw std::runtime_error("Unable to access Python context.");
    }

    c = ((PyContext*)swigo->ptr)->c;
}

void
PyAuthenticator::configure(PyObject* configuration) {
    c->resolve(authenticator);
}

void
PyAuthenticator::add_internal_subnet(const cidr_ipaddr& cidr)
{
    authenticator->add_internal_subnet(cidr);
}

bool
PyAuthenticator::remove_internal_subnet(const cidr_ipaddr& cidr)
{
    return authenticator->remove_internal_subnet(cidr);
}

void
PyAuthenticator::clear_internal_subnets()
{
    authenticator->clear_internal_subnets();
}

uint32_t
PyAuthenticator::get_authed_host(const ethernetaddr& dladdr, uint32_t nwaddr)
{
    return authenticator->get_authed_host(dladdr, nwaddr);
}

void
PyAuthenticator::get_names(const datapathid& dp, uint16_t inport,
                           const ethernetaddr& dlsrc, uint32_t nwsrc,
                           const ethernetaddr& dldst, uint32_t nwdst,
                           PyObject *callable)
{
    authenticator->get_names(dp, inport, dlsrc, nwsrc, dldst, nwdst, callable);
}

}
}

