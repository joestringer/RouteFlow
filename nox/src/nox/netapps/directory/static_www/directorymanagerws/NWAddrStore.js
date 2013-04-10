/*
 Copyright 2008 (C) Nicira, Inc.

 This file is part of NOX.

 NOX is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 NOX is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */

dojo.provide("nox.netapps.directory.directorymanagerws.NWAddrStore");

dojo.require("nox.netapps.directory.directorymanagerws._PrincipalStore");
dojo.require("nox.netapps.directory.directorymanagerws.NWAddr");

dojo.declare("nox.netapps.directory.directorymanagerws.NWAddrStore", [ nox.netapps.directory.directorymanagerws._PrincipalStore ], {

    constructor: function (kwarg) {
        this.itemConstructor = this.dmws.NWAddr
        // there is no base URL for this, it must be passed in
    }, 
    
    _unpackData: function (response) {
        var arr = [];
        dojo.forEach(response, function(i) { 
            arr.push({ "ip_str" : i }); 
        }); 
        return arr;
    }

});
// Mix in the simple fetch implementation to this class.
// TBD: Why can't this just be inherited?
dojo.extend(nox.netapps.directory.directorymanagerws.NWAddrStore,dojo.data.util.simpleFetch);
