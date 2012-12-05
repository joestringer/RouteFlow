#include "bookman-msg-event.hh"
#include "buffer.hh"
#include "async_io.hh"
#include <errno.h>
#include "errno_exception.hh"
#include <xercesc/dom/DOM.hpp>
#include "vlog.hh"

namespace vigil
{
  using namespace vigil::container;

  static Vlog_module lg("bookman-msg-event");
  static const std::string app_name("bookman-msg-event");

  Book_msg_event::Book_msg_event(book_message* message, Async_stream* socket,
				 bool isSSL_):
    Event(static_get_name())
  {
    set_message(message);
    sock = new Msg_stream(socket,isSSL_);
  }

  Book_msg_event::Book_msg_event(ssize_t size, Async_stream* socket,
				 bool isSSL_):
    Event(static_get_name())
  {
    raw_book.reset(new uint8_t[size]);
    sock = new Msg_stream(socket,isSSL_);
  }

  Book_msg_event::~Book_msg_event()
  {
    delete sock;
  }

  void Book_msg_event::set_message(book_message* message, ssize_t size)
  {
    raw_book.reset(new uint8_t[size]);
    memcpy(raw_book.get(), message, size);
    msg = (book_message*) raw_book.get();
  }

  void Book_msg_event::set_message(book_message* message)
  {
    set_message(message, ntohs(message->header.length));
  }

} // namespace vigil
