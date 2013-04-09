/* Copyright 2009 (C) Nicira, Inc.
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
%module "nox.netapps.data.pydatatypes"

%{
#include "pydatatypes.hh"

using namespace vigil;
%}

%include "common-defs.i"
%include "std_string.i"

typedef int64_t PrincipalType;
typedef int64_t AddressType;
typedef int64_t DatasourceType;
typedef int64_t ExternalType;
typedef int64_t AttributeType;
%include "pydatatypes.hh"
