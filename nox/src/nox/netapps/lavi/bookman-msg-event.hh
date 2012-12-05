#ifndef BOOKMAN_MSG_EVENT_HH__
#define BOOKMAN_MSG_EVENT_HH__

#include "messenger/messenger_core.hh"
#include "bookman-message.hh"
#include "async_io.hh"
#include <sys/time.h>
#include <boost/bind.hpp>
#include <boost/shared_array.hpp>

namespace vigil
{
  using namespace vigil::container;

  /** \brief Structure holding message to and from bookman.
   *
   * Copyright (C) Stanford University, 2008.
   * @author ykk
   * @date December 2008
   * @see bookman
   */
  struct Book_msg_event : public Event
  {
    /** Constructor.
     * Allocate memory for message.
     * @param message message
     * @param socket socket message is received with
     * @param isSSL_ indicate if connection is SSL, else TCP
     */
    Book_msg_event(book_message* message, Async_stream* socket, bool isSSL_);

    /** Constructor.
     * Allocate memory for message.
     * @param size size of message
     * @param socket socket message is received with
     * @param isSSL_ indicate if connection is SSL, else TCP
     */
    Book_msg_event(ssize_t size, Async_stream* socket, bool isSSL_);

    /** Set message in the event with that in a message buffer.
     * @param message message in a buffer
     * @param size size of message to copy
     */
    void set_message(book_message* message, ssize_t size);

    /** Set message in the event with that in a message buffer.
     * Get size from message itself.
     * @param message message in a buffer
     */
    void set_message(book_message* message);

    /** Destructor.
     */
    ~Book_msg_event();

    /** Empty constructor.
     * For use within python.
     */
    Book_msg_event() : Event(static_get_name())
    { }

    /** Static name required in NOX.
     */
    static const Event_name static_get_name()
    {
      return "Book_msg_event";
    }

    /** Array reference to hold message.
     */
    book_message* msg;
    /** Memory allocated for message.
     */
    boost::shared_array<uint8_t> raw_book;
    /** Reference to socket.
     */
    Msg_stream* sock;
  };

} // namespace vigil

#endif
