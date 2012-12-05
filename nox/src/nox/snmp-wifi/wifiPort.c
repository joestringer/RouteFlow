/*
 * Note: this file originally auto-generated by mib2c using
 *        : mib2c.scalar.conf 11805 2005-01-07 09:37:18Z dts12 $
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "wifiPort.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include "vconn.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "xtoxll.h"

/** Initializes the wifiPort module */
void
init_wifiPort(void)
{
    static oid wifiPort_oid[] = { 1,3,6,1,3,108,0,6 };

  DEBUGMSGTL(("wifiPort", "Initializing\n"));

    netsnmp_register_scalar(
        netsnmp_create_handler_registration("wifiPort", handle_wifiPort,
                               wifiPort_oid, OID_LENGTH(wifiPort_oid),
                               HANDLER_CAN_RONLY
        ));
}

int
handle_wifiPort(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
        struct ofpbuf *request;
        struct vconn *vconn;
        struct ofpbuf *reply;
        struct ofp_switch_features *osf;
        struct ofp_phy_port *opp;
        uint16_t size;
        int i;
        char wifi_port[16];

        time_init();
        make_openflow(sizeof(struct ofp_header),OFPT_FEATURES_REQUEST , &request);
        update_openflow_length(request);
        vconn_open_block(DATAPATH, OFP_VERSION, &vconn);
        vconn_transact(vconn, request, &reply);
        vconn_close(vconn);

        osf = (struct ofp_switch_features*) reply->data;
        size = (ntohs(osf->header.length)-
                        sizeof(struct ofp_switch_features))/sizeof(struct ofp_phy_port);
        opp = (struct ofp_phy_port*) osf->ports;
        for (i = 0; i < size; i++)
        {
                if(strcmp(opp->name, INTERFACE) == 0) {
                        sprintf(wifi_port, "%"PRIx16"", ntohs(opp->port_no));
                        break;
                }
                opp++;
        }
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */

    switch(reqinfo->mode) {

        case MODE_GET:
                printf("wifiPort MODE_GET\n");
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                     (u_char *) wifi_port, strlen(wifi_port));
            break;


        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_wifiPort\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

                printf("wifiPort - return\n");
    return SNMP_ERR_NOERROR;
}
