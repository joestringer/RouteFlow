/*! \mainpage NOX
 *
 * \section com_list Component Listing
 * The following is a listing of components that is under heavy development.
 * <UL>
 * <LI>vigil::messenger acts as interface for external programs in the data
 * plane to communicate with NOX.  Messages can be parsed and posted as
 * different events or posted natively as a message event.
 * </LI>
 * <LI>vigil::sqlitelog helps logging into the SQLite database.
 * </LI>
 * <LI>vigil::routeinstaller installs route for a certain flow.
 * </LI>
 * </UL>
 *
 * \section dev_com_list Developing Component Listing
 * The following is a listing of components that is under heavy development.
 * <UL>
 * <LI>vigil::dhcp is a component that proxy dhcp requests and replies directly
 * to the DHCP server and requestt clients.
 * </LI>
 * <LI>vigil::eventlogger logs events in the network.
 * </LI>
 * <LI>vigil::lavi is the backend component for monitoring the network.
 * </LI>
 * <LI>vigil::MobileDB tracks location of the mobiles via SNMP.
 * </LI>
 * <LI>vigil::FlowDB tracks flows in the network using flow entries issued
 * and expiration.
 * </LI>
 * <LI>vigil::Snmp and vigil::snmptrap are used for communication with SNMP.
 * This is meant as one of the primary means for device control.
 * </LI>
 * <LI>vigil::openflowpackets used to pack OpenFlow packets, and assign
 * unique xid to messages.
 * </LI>
 * <LI>vigil::apdb used for store information about APs.
 * </LI>
 * </UL>
 *
 * \section py_lib Python Libraries
 * <UL>
 * <LI>noxmsg.py provides the basic message packing need for a Python
 * client of vigil::messenger.
 * </LI>
 * </UL>
 */
