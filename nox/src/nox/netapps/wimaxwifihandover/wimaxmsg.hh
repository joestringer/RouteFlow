#ifndef wimaxmsg_HH
#define wimaxmsg_HH 1


  /** WiMAX message subtype.
   */
  enum
  {
    /** Host join event.
     */
    WIMAX_JOIN = 0x01,
    /** Host leave event.
     */
    WIMAX_LEAVE = 0x02,
  };

  /** Message for WiMAX client association/disassociation.
   */
  struct wimax_msg
  {
    /** WiMAX subtype.
     */
    uint8_t subtype;
    /** Host mac address.
     */
    uint64_t host_mac;
    /** Base station mac address.
     */
    uint64_t bs_mac;
    /** Wireless port number.
     */
    uint16_t port;
  };
#endif
