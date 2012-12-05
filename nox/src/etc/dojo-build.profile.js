dependencies = {

    layers: [
		{
			name: "../dijit/dijit.js",
			dependencies: [
				"dijit.dijit"
			]
		},
		{
			name: "../dijit/dijit-all.js",
			layerDependencies: [
				"../dijit/dijit.js"
			],
			dependencies: [
				"dijit.dijit-all"
			]
		},
        {
            name: "../nox/uiapps/coreui/coreui/noxcore.js",
            resourceName: "nox.uiapps.coreui.coreui.noxcore",
            layerDependencies: [ ],
            dependencies: [ "nox.uiapps.coreui.coreui.noxcore" ]
            copyrightFile: "../../nox/uiapps/coreui/coreui/nox-js-copyright.txt"
        }
    ],

    prefixes: [
        [ "dijit", "../dijit" ],
        [ "dojox", "../dojox" ],
        [ "nox", "../nox", "../../nox/apps/coreui/coreui/nox-js-copyright.txt" ]
    ]

}
