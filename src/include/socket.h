#ifndef FILEZILLA_ENGINE_SOCKET_HEADER
#define FILEZILLA_ENGINE_SOCKET_HEADER

#include <libfilezilla/event_handler.hpp>
#include <libfilezilla/iputils.hpp>

#include <errno.h>

/// \private
struct sockaddr;

namespace fz {
class thread_pool;

enum class socket_event_flag
{
	// This is a nonfatal condition. It
	// means there are additional addresses to try.
	connection_next,

	connection,
	read,
	write
};

/**
 * \brief All classes sending socket events should derive from this.
 *
 * Allows implementing socket layers, e.g. for TLS.
 *
 * \sa fz::RemoveSocketEvents
 * \sa fz::ChangeSocketEventHandler
 */
class socket_event_source
{
public:
	virtual ~socket_event_source() = default;
};

/// \private
struct socket_event_type;

/**
 * All socket events are sent through this.
 *
 * \sa \ref fz::socket_event_flag
 *
 * If the error value is non-zero for the connection, read and write events,
 * the socket has failed and needs to be closed. Doing anything else with
 * failed sockets is undefined behavior. 
 * Failure events can be received at any time.
 *
 * Read and write events are edge-triggered:
 * - After receiving a read event for a socket, it will not be sent again unless
 * a subsequent call to socket::read has returned EAGAIN.
 * - The same holds for the write event and socket::write
 */
typedef simple_event<socket_event_type, socket_event_source*, socket_event_flag, int> socket_event;

/// \private
struct hostaddress_event_type;

/**
* Whenever a hostname has been resolved to an IP address, this event is sent with the resolved IP address literal.
*/
typedef simple_event<hostaddress_event_type, socket_event_source*, std::string> hostaddress_event;

/**
 * \brief Remove all pending socket events from source sent to handler.
 *
 * Useful e.g. if you want to destroy the handler but keep the source.
 * This function is called, through change_socket_event_handler, by socket::set_event_handler(0)
 */
void remove_socket_events(event_handler * handler, socket_event_source const* const source);

/**
 * \brief Changes all pending socket events from source
 *
 * If newHandler is null, remove_socket_events is called.
 *
 * This function is called by socket::set_event_handler().
 *
 * \example Possible use-cases: Handoff after proxy handshakes, or handoff to TLS classes in
			case of STARTTLS mechanism
 */
void change_socket_event_handler(event_handler * old_handler, event_handler * new_handler, socket_event_source const* const source);

/// \private
class socket_thread;

/// \private
class socket_base : public socket_event_source
{
public:
	enum
	{
		/// flag_nodelay disables Nagle's algorithm
		flag_nodelay = 0x01,

		/// flag_keepalive enables TCP keepalive.
		flag_keepalive = 0x02
	};

	int flags() const { return flags_; }
	void set_flags(int flags);

	/**
	 * \brief Sets socket buffer sizes.
	 *
	 * Internally this sets SO_RCVBUF and SO_SNDBUF on the socket.
	 *
	 * If called on listen socket, sizes will be inherited by accepted sockets.
	 */
	int set_buffer_sizes(int size_receive, int size_send);

	/**
	 * Sets the interval between TCP keepalive packets.
	 *
	 * Duration must not be smaller than 5 minutes. The default interval is 2 hours.
	 */
	void set_keepalive_interval(duration const& d);

	/// If connected, either ipv4 or ipv6, unknown otherwise
	address_type address_family() const;

	/**
	 * \brief Returns local address of a connected socket
	 *
	 * \return empty string on error
	 */
	std::string local_ip(bool strip_zone_index = false) const;

	/**
	* \brief Returns local port of a connected socket
	*
	* \return -1 on error
	*/
	int local_port(int& error);

	static std::string address_to_string(sockaddr const* addr, int addr_len, bool with_port = true, bool strip_zone_index = false);
	static std::string address_to_string(char const* buf, int buf_len);

	int close();

	void set_event_handler(event_handler* pEvtHandler);

protected:
	friend class socket_thread;

	socket_base(thread_pool& pool, event_handler* evt_handler);

	// Note: Unlocks the lock.
	void detach_thread(scoped_lock & l);

	thread_pool & thread_pool_;
	event_handler* evt_handler_;

	int fd_{-1};

	socket_thread* socket_thread_{};

	unsigned int port_{};

	int family_;

	int flags_{};
	duration keepalive_interval_;

	int buffer_sizes_[2];

	int state_{};
};

class socket;

class listen_socket final : public socket_base
{
	friend class socket_thread;
public:
	listen_socket(thread_pool& pool, event_handler* evt_handler);
	virtual ~listen_socket();

	listen_socket(listen_socket const&) = delete;
	listen_socket& operator=(listen_socket const&) = delete;

	int listen(address_type family, int port = 0);
	socket* accept(int& error);

	enum listen_socket_state
	{
		// How the socket is initially
		none,

		// Only in listening state you can get a connection event.
		listening
	};
	listen_socket_state get_state();
};

/**
 * \brief IPv6 capable, non-blocking socket class
 *
 * Uses and edge-triggered socket events.
 *
 * Error codes are the same as used by the POSIX socket functions,
 * see 'man 2 socket', 'man 2 connect', ...
 */
class socket final : public socket_base
{
	friend class socket_thread;
public:
	socket(thread_pool& pool, event_handler* evt_handler);
	virtual ~socket();

	socket(socket const&) = delete;
	socket& operator=(socket const&) = delete;

	enum socket_state
	{
		// How the socket is initially
		none,

		// Only in connecting state you can get a connection event.
		// After sending the event, socket is in connected state
		connecting,

		// Only in this state you can get send or receive events
		connected,

		closed
	};
	socket_state get_state();

	// Connects to the given host, given as name, IPv4 or IPv6 address.
	// Returns 0 on success, else an error code. Note: EINPROGRESS is
	// not really an error. On success, you should still wait for the
	// connection event.
	// If host is a name that can be resolved, a hostaddress socket event gets
	// sent.
	// Once connections got established or establishment fails, a connection
	// event gets sent, with the error parameter indicating success or failur.
	// connection could not be established, a connection event with an error event gets sent.
	int connect(native_string const& host, unsigned int port, address_type family = address_type::unknown, std::string const& bind = std::string());

	// After receiving a send or receive event, you can call these functions
	// as long as their return value is positive.
	int read(void *buffer, unsigned int size, int& error);
	int peek(void *buffer, unsigned int size, int& error);
	int write(const void *buffer, unsigned int size, int& error);

	/**
	* \brief Returns remote address of a connected socket
	*
	* \return empty string on error
	*/
	std::string peer_ip(bool strip_zone_index = false) const;

	/// Returns the hostname passed to Connect()
	native_string peer_host() const;

	/**
	* \brief Returns remote port of a connected socket
	*
	* \return -1 on error
	*/
	int remote_port(int& error);

	/**
	 * On a connected socket, gets the ideal send buffer size or
	 * -1 if it cannot be determined.
	 *
	 * Currently only implemented for Windows.
	 */
	int ideal_send_buffer_size();

	/**
	 * Allows re-triggering the read and write events.
	 * Slow and cumbersome, use sparingly.
	 */
	void retrigger(socket_event_flag event);

	/**
	 * \brief Signals peers that we want to close the connections.
	 *
	 * Implicitly done through close.
	 */
	int shutdown();

private:
	friend class listen_socket;
	native_string host_;
};

#ifdef FZ_WINDOWS

#ifndef EISCONN
#define EISCONN WSAEISCONN
#endif
#ifndef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#endif
#ifndef EADDRINUSE
#define EADDRINUSE WSAEADDRINUSE
#endif
#ifndef ENOBUFS
#define ENOBUFS WSAENOBUFS
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#endif
#ifndef EALREADY
#define EALREADY WSAEALREADY
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED WSAECONNREFUSED
#endif
#ifndef ENOTSOCK
#define ENOTSOCK WSAENOTSOCK
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT WSAETIMEDOUT
#endif
#ifndef ENETUNREACH
#define ENETUNREACH WSAENETUNREACH
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH WSAEHOSTUNREACH
#endif
#ifndef ENOTCONN
#define ENOTCONN WSAENOTCONN
#endif
#ifndef ENETRESET
#define ENETRESET WSAENETRESET
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP WSAEOPNOTSUPP
#endif
#ifndef ESHUTDOWN
#define ESHUTDOWN WSAESHUTDOWN
#endif
#ifndef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE
#endif
#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif
#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#endif
#ifndef EHOSTDOWN
#define EHOSTDOWN WSAEHOSTDOWN
#endif

// For the future:
// Handle ERROR_NETNAME_DELETED=64
#endif //FZ_WINDOWS

}

#endif
