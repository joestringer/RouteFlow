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


/* Mixin to provide retrieval for information about Directories  */

dojo.provide("nox.netapps.directory.directorymanagerws.DirectoryStore");

dojo.require("nox.netapps.directory.directorymanagerws.Directory");
dojo.require("nox.uiapps.coreui.coreui._UpdatingStore");
dojo.require("dojo.data.util.simpleFetch");

dojo.declare("nox.netapps.directory.directorymanagerws.DirectoryStore", 
             [ nox.uiapps.coreui.coreui._UpdatingStore ], {

    dmws: nox.netapps.directory.directorymanagerws,

    constructor: function (kwarg) {
        this.itemConstructor = this.dmws.Directory;
        if (this.url == null)
            this.url = "/ws.v1/directory/instance";
    },

    _unpackData: function (response) {
        var i = 0;
        return dojo.map(response.items, function (d) {
            d.search_order = i++;
            return d;
        });
    }
});

//Mix in the simple fetch implementation to this class.
// TBD: Why can't this just be inherited?
dojo.extend(nox.netapps.directory.directorymanagerws.DirectoryStore,
            dojo.data.util.simpleFetch);
