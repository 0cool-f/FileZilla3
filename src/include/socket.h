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

	/** \brief Gets the root source
	 *
	 * In a layered stack of sources this would be the socket itself.
	 */
	socket_event_source* root() const {
		return root_;
	}

protected:
	socket_event_source() = default;
	explicit socket_event_source(socket_event_source* root)
		: root_(root)
	{}

	socket_event_source* const root_{};
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

/// Common base clase for fz::socket and fz::listen_socket
class socket_base
{
public:
	/**
	 * \brief Sets socket buffer sizes.
	 *
	 * Internally this sets SO_RCVBUF and SO_SNDBUF on the socket.
	 *
	 * If called on listen socket, sizes will be inherited by accepted sockets.
	 */
	int set_buffer_sizes(int size_receive, int size_send);

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

	/**
	 * \brief Bind socket to the specific local IP
	 *
	 * Undefined after having called connect/listen
	 */
	bool bind(std::string const& address);

#if FZ_WINDOWS
	typedef intptr_t socket_t;
#else
	typedef int socket_t;
#endif

protected:
	friend class socket_thread;

	socket_base(thread_pool& pool, event_handler* evt_handler, socket_event_source* ev_source);
	virtual ~socket_base() = default;

	int close();

	void do_set_event_handler(event_handler* pEvtHandler);

	// Note: Unlocks the lock.
	void detach_thread(scoped_lock & l);

	thread_pool & thread_pool_;
	event_handler* evt_handler_;

	socket_t fd_{-1};

	socket_thread* socket_thread_{};

	unsigned int port_{};

	int family_;

	int buffer_sizes_[2];

	socket_event_source * const ev_source_{};
};

class socket;

enum class listen_socket_state
{
	/// How the socket is initially
	none,

	/// Only in listening state you can get a connection event.
	listening,
};

class listen_socket final : public socket_base, public socket_event_source
{
	friend class socket_base;
	friend class socket_thread;
public:
	listen_socket(thread_pool& pool, event_handler* evt_handler);
	virtual ~listen_socket();

	listen_socket(listen_socket const&) = delete;
	listen_socket& operator=(listen_socket const&) = delete;

	int listen(address_type family, int port = 0);
	socket* accept(int& error);

	listen_socket_state get_state();

	void set_event_handler(event_handler* pEvtHandler) {
		do_set_event_handler(pEvtHandler);
	}

private:
	listen_socket_state state_{};
};


/// State transitions are monotonically increasing
enum class socket_state
{
	/// How the socket is initially
	none,

	/// Only in connecting state you can get a connection event.
	/// After sending the event, socket is in connected or failed state
	/// depending whether error value is set in the event.
	connecting,

	/// Socket is in its normal working state. You can get send and receive events
	connected,

	/// Shutting down of the write side. Transitions to
	/// shutdown with a single write event.
	shutting_down,

	/// Write side has finished shutting down. Receive still working normally.
	shut_down,

	/// Socket has been closed. Further events disabled.
	closed,

	/// Socket has failed. Further events disabled.
	failed
};

class socket_interface : public socket_event_source
{
public:
	socket_interface(socket_interface const&) = delete;
	socket_interface& operator=(socket_interface const&) = delete;


	virtual int read(void* buffer, unsigned int size, int& error) = 0;
	virtual int write(void const* buffer, unsigned int size, int& error) = 0;

	virtual void set_event_handler(event_handler* pEvtHandler) = 0;

	virtual native_string peer_host() const = 0;
	virtual int peer_port(int& error) const = 0;

	virtual int connect(native_string const& host, unsigned int port, address_type family = address_type::unknown) = 0;

	virtual fz::socket_state get_state() const = 0;
	
protected:
	socket_interface() = default;
	
	explicit socket_interface(socket_event_source * root)
		: socket_event_source(root)
	{}
};

/**
 * \brief IPv6 capable, non-blocking socket class
 *
 * Uses and edge-triggered socket events.
 *
 * Error codes are the same as used by the POSIX socket functions,
 * see 'man 2 socket', 'man 2 connect', ...
 */
class socket final : public socket_base, public socket_interface
{
	friend class socket_thread;
public:
	socket(thread_pool& pool, event_handler* evt_handler);
	virtual ~socket();

	socket(socket const&) = delete;
	socket& operator=(socket const&) = delete;

	socket_state get_state() const override;
	bool is_connected() const {
		socket_state s = get_state();
		return s == socket_state::connected || s == socket_state::shutting_down || s == socket_state::shut_down;
	};

	/**
	 * \brief Starts connecting to the given host, given as name, IPv4 or IPv6 address.
	 *
	 * Returns 0 on success, else an error code.
	 *
	 * Success only means that the establishing of the connection
	 * has started. Once the connection gets fully established or
	 * establishment fails, a connection event gets sent, with the error
	 * parameter indicating success or failure.
	 *
	 * If host is a name that can be resolved, a hostaddress socket event gets
	 * sent during establishment.
	 */
	virtual int connect(native_string const& host, unsigned int port, address_type family = address_type::unknown) override;

	/**
	 * \brief Read data from socket
	 *
	 * Reads data from socket, returns the number of octets read or -1 on error.
	 *
	 * May return fewer  octets than requested. Return of 0 bytes read indicates EOF.
	 *
	 * Can be called after having receiving a socket event with the read
	 * flag and can thenceforth be called until until it returns an error.
	 *
	 * If the error is EAGAIN, wait for the next read event. On other errors
	 * the socket has failed and should be closed.
	 *
	 * Takes care of EINTR internally.
	 */
	virtual int read(void *buffer, unsigned int size, int& error) override;

	/**
	 * \brief Write data to socket
	 *
	 * Writes data to the socket, returns the number of octets written or -1 on error.
	 *
	 * May return fewer octets than requested.
	 *
	 * Can be called after having receiving a socket event with the write
	 * flag and can thenceforth be called until until it returns an error.
	 *
	 * If the error is EAGAIN, wait for the next write event. On other errors
	 * the socket has failed and should be closed.
	 *
	 * Takes care of EINTR internally.
	 */
	virtual int write(void const* buffer, unsigned int size, int& error) override;

	/**
	* \brief Returns remote address of a connected socket
	*
	* \return empty string on error
	*/
	std::string peer_ip(bool strip_zone_index = false) const;

	/// Returns the hostname passed to connect()
	virtual native_string peer_host() const override;

	/**
	* \brief Returns remote port of a connected socket
	*
	* \return -1 on error
	*/
	virtual int peer_port(int& error) const override;

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

	virtual void set_event_handler(event_handler* pEvtHandler) override;

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
	 * Sets the interval between TCP keepalive packets.
	 *
	 * Duration must not be smaller than 5 minutes. The default interval is 2 hours.
	 */
	void set_keepalive_interval(duration const& d);

private:
	friend class socket_base;
	friend class listen_socket;
	native_string host_;

	socket_state state_{};

	int flags_{};
	duration keepalive_interval_;
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
