#include <libfilezilla/libfilezilla.hpp>
#ifdef FZ_WINDOWS
  #include <libfilezilla/private/windows.hpp>
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
  #include <netdb.h>
#endif
#include <filezilla.h>
#include "engineprivate.h"
#include "proxy.h"
#include "socket_errors.h"
#include "ControlSocket.h"

#include <libfilezilla/iputils.hpp>

#include <algorithm>

#include <string.h>

enum handshake_state
{
	http_wait,

	socks5_method,
	socks5_auth,
	socks5_request,

	socks4_handshake
};

CProxySocket::CProxySocket(fz::event_handler* pEvtHandler, fz::socket_interface & next_layer, CControlSocket* pOwner)
	: fz::event_handler(pOwner->event_loop_)
	, SocketLayer(pEvtHandler, next_layer, false)
	, m_pOwner(pOwner)
{
	next_layer_.set_event_handler(this);
}

CProxySocket::~CProxySocket()
{
	remove_handler();
}

std::wstring CProxySocket::Name(ProxyType t)
{
	switch (t) {
	case HTTP:
		return L"HTTP";
	case SOCKS4:
		return L"SOCKS4";
	case SOCKS5:
		return L"SOCKS5";
	default:
		return _("unknown");
	}
}

int CProxySocket::Handshake(CProxySocket::ProxyType type, fz::native_string const& host, unsigned int port, std::wstring const& user, std::wstring const& pass)
{
	if (type == CProxySocket::unknown || host.empty() || port < 1 || port > 65535) {
		return EINVAL;
	}

	if (m_proxyState != noconn) {
		return EALREADY;
	}

	if (type != HTTP && type != SOCKS5 && type != SOCKS4) {
		return EPROTONOSUPPORT;
	}

	m_user = fz::to_utf8(user);
	m_pass = fz::to_utf8(pass);
	host_ = host;
	port_ = static_cast<int>(port);
	m_proxyType = type;

	m_proxyState = handshake;

	if (type == HTTP) {
		m_handshakeState = http_wait;

		std::string auth;
		if (!user.empty()) {
			auth = "Proxy-Authorization: Basic ";
			auth += fz::base64_encode(m_user + ":" + m_pass);
			auth += "\r\n";
		}

		// Bit oversized, but be on the safe side
		std::string host_raw = fz::to_utf8(host);
		sendBuffer_.append(fz::sprintf("CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n%sUser-Agent: %s\r\n\r\n",
			host_raw, port,
			host_raw, port,
			auth,
			fz::replaced_substrings(PACKAGE_STRING, " ", "/")));
	}
	else if (type == SOCKS4) {
		std::string ip;
		auto const addressType = fz::get_address_type(host_);
		if (addressType == fz::address_type::ipv6) {
			m_pOwner->LogMessage(MessageType::Error, _("IPv6 addresses are not supported with SOCKS4 proxy"));
			return EINVAL;
		}
		else if (addressType == fz::address_type::ipv4) {
			ip = fz::to_string(host_);
		}
		else {
			addrinfo hints{};
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;

			addrinfo * result{};
			int res = getaddrinfo(fz::to_string(host_).c_str(), nullptr, &hints, &result);
			if (!res && result) {
				if (result->ai_family == AF_INET) {
					ip = fz::socket::address_to_string(result->ai_addr, result->ai_addrlen, false);
				}
				freeaddrinfo(result);
			}

			if (ip.empty()) {
				m_pOwner->LogMessage(MessageType::Error, _("Cannot resolve hostname to IPv4 address for use with SOCKS4 proxy."));
				return EINVAL;
			}
		}

		m_pOwner->LogMessage(MessageType::Status, _("SOCKS4 proxy will connect to: %s"), ip);

		unsigned char* out = sendBuffer_.get(9);
		out[0] = 4; // Protocol version
		out[1] = 1; // Stream mode
		out[2] = (port_ >> 8) & 0xFF; // Port in network order
		out[3] = port_ & 0xFF;
		int i = 0;
		memset(out + 4, 0, 5);
		for (auto p = ip.c_str(); *p && i < 4; ++p) {
			auto const& c = *p;
			if (c == '.') {
				++i;
				continue;
			}
			out[i + 4] *= 10;
			out[i + 4] += c - '0';
		}
		sendBuffer_.add(9);

		m_handshakeState = socks4_handshake;
	}
	else {
		if (m_user.size() > 255 || m_pass.size() > 255) {
			m_pOwner->LogMessage(MessageType::Status, _("SOCKS5 does not support usernames or passwords longer than 255 characters."));
			return EINVAL;
		}

		unsigned char* out = sendBuffer_.get(4);
		out[0] = 5; // Protocol version
		if (!user.empty()) {
			out[1] = 2; // # auth methods supported
			out[2] = 0; // Method: No auth
			out[3] = 2; // Method: Username and password
			sendBuffer_.add(4);
		}
		else {
			out[1] = 1; // # auth methods supported
			out[2] = 0; // Method: No auth
			sendBuffer_.add(3);
		}

		m_handshakeState = socks5_method;
	}

	return EINPROGRESS;
}

void CProxySocket::operator()(fz::event_base const& ev)
{
	fz::dispatch<fz::socket_event, fz::hostaddress_event>(ev, this,
		&CProxySocket::OnSocketEvent,
		&CProxySocket::OnHostAddress);
}

void CProxySocket::OnSocketEvent(socket_event_source* s, fz::socket_event_flag t, int error)
{
	if (m_proxyState != handshake) {
		return;
	}

	if (t == fz::socket_event_flag::connection_next) {
		forward_event(s, t, error);
		return;
	}

	if (error) {
		m_proxyState = noconn;
		forward_event(s, t, error);
		return;
	}

	switch (t) {
	case fz::socket_event_flag::connection:
		m_pOwner->LogMessage(MessageType::Status, _("Connection with proxy established, performing handshake..."));
		break;
	case fz::socket_event_flag::read:
		OnReceive();
		break;
	case fz::socket_event_flag::write:
		OnSend();
		break;
	default:
		break;
	}
}

void CProxySocket::OnHostAddress(socket_event_source*, std::string const& address)
{
	m_pOwner->LogMessage(MessageType::Status, _("Connecting to %s..."), address);
}

void CProxySocket::OnReceive()
{
	m_can_read = true;

	if (m_proxyState != handshake) {
		return;
	}

	while (m_can_read) {
		loop:
		int to_read = 1024;
		unsigned char* buf = receiveBuffer_.get(to_read);

		int error;
		int read = next_layer_.read(buf, to_read, error);

		if (read < 0) {
			if (error != EAGAIN) {
				m_proxyState = noconn;
				if (m_pEvtHandler) {
					m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, error);
				}
			}
			else {
				m_can_read = false;
			}
			return;
		}
		if (!read) {
			m_proxyState = noconn;
			if (m_pEvtHandler) {
				m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNABORTED);
			}
			return;
		}
		receiveBuffer_.add(read);

		switch (m_handshakeState) {
		case http_wait:
			{
				// Look for \r\n\r\n
				buf = receiveBuffer_.get();
				size_t i = 0;
				for (i = 0; i + 4 <= receiveBuffer_.size(); ++i) {
					if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == 'r' && buf[i + 3] == '\n') {
						break;
					}
				}
				if (i + 4 > receiveBuffer_.size()) {
					// Not found yet
					if (receiveBuffer_.size() >= 2048) {
						m_proxyState = noconn;
						m_pOwner->LogMessage(MessageType::Debug_Warning, L"Incoming header too large");
						if (m_pEvtHandler) {
							m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ENOMEM);
						}
						return;
					}
					break;
				}

				// Found end of header
				unsigned char* eol = reinterpret_cast<unsigned char*>(strchr(reinterpret_cast<char*>(buf), '\r')); // Never fails as old buf ends on CRLFCRLF
				*eol = 0;
				std::wstring const reply = fz::to_wstring_from_utf8(std::string(reinterpret_cast<char*>(buf))); // Terminate at first emedded null
				m_pOwner->LogMessage(MessageType::Response, _("Proxy reply: %s"), reply);

				if (reply.substr(0, 10) != L"HTTP/1.1 2" && reply.substr(0, 10) != L"HTTP/1.0 2") {
					m_proxyState = noconn;
					if (m_pEvtHandler) {
						m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNRESET);
					}
				}
				else {
					m_proxyState = conn;
					if (m_pEvtHandler) {
						m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, 0);
					}
					receiveBuffer_.consume(i + 4);
					set_event_passthrough(true);
				}
				return;
			}
		case socks4_handshake:
			{
				if (receiveBuffer_.size() < 8) {
					break;
				}

				unsigned char const* const buf = receiveBuffer_.get();
				if (buf[1] != 0x5A) {
					std::wstring error;
					switch (buf[1]) {
						case 0x5B:
							error = _("Request rejected or failed");
							break;
						case 0x5C:
							error = _("Request failed - client is not running identd (or not reachable from server)");
							break;
						case 0x5D:
							error = _("Request failed - client's identd could not confirm the user ID string");
							break;
						default:
							error = fz::sprintf(_("Unassigned error code %d"), (int)buf[1]);
							break;
					}
					m_pOwner->LogMessage(MessageType::Error, _("Proxy request failed: %s"), error);
					m_proxyState = noconn;
					if (m_pEvtHandler) {
						m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNABORTED);
					}
				}
				else {
					m_proxyState = conn;
					if (m_pEvtHandler) {
						m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, 0);
					}
					receiveBuffer_.consume(8);
					set_event_passthrough(true);
				}
				return;
			}
		case socks5_method:
		case socks5_auth:
		case socks5_request:
			if (sendBuffer_) {
				m_pOwner->LogMessage(MessageType::Error, _("Proxy sent data while we haven't sent out request yet"));
				m_proxyState = noconn;
				if (m_pEvtHandler) {
					m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNABORTED);
				}
				return;
			}
			
			// All data got read, parse it
			switch (m_handshakeState) {
			default:
				if (receiveBuffer_[0] != 5) {
					m_pOwner->LogMessage(MessageType::Error, _("Unknown SOCKS protocol version: %d"), (int)receiveBuffer_[0]);
					m_proxyState = noconn;
					if (m_pEvtHandler) {
						m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNABORTED);
					}
					return;
				}
				break;
			case socks5_auth:
				if (receiveBuffer_[0] != 1) {
					m_pOwner->LogMessage(MessageType::Error, _("Unknown protocol version of SOCKS Username/Password Authentication subnegotiation: %d"), receiveBuffer_[0]);
					m_proxyState = noconn;
					if (m_pEvtHandler) {
						m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNABORTED);
					}
					return;
				}
				break;
			}

			switch (m_handshakeState) {
				case socks5_method:
				{
					if (receiveBuffer_.size() < 2) {
						goto loop;
					}
					char const method = receiveBuffer_[1];
					switch (method)
					{
					case 0:
						m_handshakeState = socks5_request;
						break;
					case 2:
						m_handshakeState = socks5_auth;
						break;
					default:
						m_pOwner->LogMessage(MessageType::Error, _("No supported SOCKS5 auth method"));
						m_proxyState = noconn;
						if (m_pEvtHandler) {
							m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNABORTED);
						}
						return;
					}
					receiveBuffer_.consume(2);
				}
				break;
			case socks5_auth:
				if (receiveBuffer_.size() < 2) {
					goto loop;
				}
				if (receiveBuffer_[1] != 0) {
					m_pOwner->LogMessage(MessageType::Error, _("Proxy authentication failed"));
					m_proxyState = noconn;
					if (m_pEvtHandler) {
						m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNABORTED);
					}
					return;
				}
				m_handshakeState = socks5_request;
				receiveBuffer_.consume(2);
				break;
			case socks5_request:
				if (receiveBuffer_.size() < 2) {
					goto loop;
				}
				if (receiveBuffer_[1]) {
					std::wstring errorMsg;
					switch (receiveBuffer_[1])
					{
					case 1:
						errorMsg = _("General SOCKS server failure");
						break;
					case 2:
						errorMsg = _("Connection not allowed by ruleset");
						break;
					case 3:
						errorMsg = _("Network unreachable");
						break;
					case 4:
						errorMsg = _("Host unreachable");
						break;
					case 5:
						errorMsg = _("Connection refused");
						break;
					case 6:
						errorMsg = _("TTL expired");
						break;
					case 7:
						errorMsg = _("Command not supported");
						break;
					case 8:
						errorMsg = _("Address type not supported");
						break;
					default:
						errorMsg = fz::sprintf(_("Unassigned error code %d"), receiveBuffer_[1]);
						break;
					}

					m_pOwner->LogMessage(MessageType::Error, _("Proxy request failed. Reply from proxy: %s"), errorMsg);
					m_proxyState = noconn;
					if (m_pEvtHandler) {
						m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNABORTED);
					}
					return;
				}

				// We need to parse the returned address type to determine the length of the address that follows.
				// Unfortunately the information in the type and address is useless, many proxies just return
				// syntactically valid bogus values
				if (receiveBuffer_.size() < 4) {
					goto loop;
				}
				switch (receiveBuffer_[3])
				{
				case 1:
					// syntactically valid bogus values
					if (receiveBuffer_.size() < 10) {
						goto loop;
					}
					receiveBuffer_.consume(10);
					break;
				case 3:
					if (receiveBuffer_.size() < 5) {
						goto loop;
					}
					if (receiveBuffer_.size() < receiveBuffer_[4] + 7) {
						goto loop;
					}
					receiveBuffer_.consume(receiveBuffer_[4] + 7);
					break;
				case 4:
					if (receiveBuffer_.size() < 22) {
						goto loop;
					}
					receiveBuffer_.consume(22);
					break;
				default:
					m_pOwner->LogMessage(MessageType::Error, _("Proxy request failed: Unknown address type in CONNECT reply"));
					m_proxyState = noconn;
					if (m_pEvtHandler) {
						m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNABORTED);
					}
					return;
				}

				// We're done
				m_proxyState = conn;
				if (m_pEvtHandler) {
					m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, 0);
				}
				set_event_passthrough(true);
				return;
			default:
				assert(false);
				break;
			}

			switch (m_handshakeState)
			{
			case socks5_auth:
				{
					auto ulen = static_cast<unsigned char>(std::min(m_user.size(), size_t(255)));
					auto plen = static_cast<unsigned char>(std::min(m_pass.size(), size_t(255)));
					unsigned char* out = sendBuffer_.get(ulen + plen + 3);
					out[0] = 1;
					out[1] = ulen;
					memcpy(out + 2, m_user.c_str(), ulen);
					out[ulen + 2] = plen;
					memcpy(out + ulen + 3, m_pass.c_str(), plen);
					sendBuffer_.add(ulen + plen + 3);
				}
				break;
			case socks5_request:
				{
					std::string host = fz::to_utf8(host_);
					size_t addrlen = std::max(host.size(), size_t(16));

					unsigned char * out = sendBuffer_.get(7 + addrlen);
					out[0] = 5;
					out[1] = 1; // CONNECT
					out[2] = 0; // Reserved

					auto const type = fz::get_address_type(host);
					if (type == fz::address_type::ipv6) {
						auto ipv6 = fz::get_ipv6_long_form(host);
						addrlen = 16;
						for (auto i = 0; i < 16; ++i) {
							out[4 + i] = (fz::hex_char_to_int(ipv6[i * 2 + i / 2]) << 4) + fz::hex_char_to_int(ipv6[i * 2 + 1 + i / 2]);
						}

						out[3] = 4; // IPv6
					}
					else if (type == fz::address_type::ipv4) {
						int i = 0;
						memset(out + 4, 0, 4);
						for (auto p = host.c_str(); *p && i < 4; ++p) {
							auto const& c = *p;
							if (c == '.') {
								++i;
								continue;
							}
							out[i + 4] *= 10;
							out[i + 4] += c - '0';
						}

						addrlen = 4;

						out[3] = 1; // IPv4
					}
					else {
						out[3] = 3; // Domain name

						auto hlen = static_cast<unsigned char>(std::min(host.size(), size_t(255)));
						out[4] = hlen;
						memcpy(out + 5, host.c_str(), hlen);
						addrlen = hlen + 1;
					}

					out[addrlen + 4] = (port_ >> 8) & 0xFF; // Port in network order
					out[addrlen + 5] = port_ & 0xFF;

					sendBuffer_.add(6 + addrlen);
				}
				break;
			default:
				assert(false);
				break;
			}
			if (sendBuffer_ && m_can_write) {
				OnSend();
			}
			break;
		default:
			m_proxyState = noconn;
			m_pOwner->LogMessage(MessageType::Debug_Warning, L"Unhandled handshake state %d", m_handshakeState);
			if (m_pEvtHandler) {
				m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, ECONNABORTED);
			}
			return;
		}
	}
}

void CProxySocket::OnSend()
{
	m_can_write = true;
	if (m_proxyState != handshake || !sendBuffer_) {
		return;
	}

	for (;;) {
		int error;
		int written = next_layer_.write(sendBuffer_.get(), sendBuffer_.size(), error);
		if (written == -1) {
			if (error != EAGAIN) {
				m_proxyState = noconn;
				if (m_pEvtHandler) {
					m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::connection, error);
				}
			}
			else {
				m_can_write = false;
			}

			return;
		}

		sendBuffer_.consume(written);
		if (sendBuffer_.empty()) {
			if (m_can_read) {
				OnReceive();
			}
			return;
		}
	}
}

int CProxySocket::read(void * buffer, unsigned int size, int& error)
{
	if (receiveBuffer_) {
		if (size > receiveBuffer_.size()) {
			size = receiveBuffer_.size();
		}
		memcpy(buffer, receiveBuffer_.get(), size);
		receiveBuffer_.consume(size);
		return size;
	}
	return next_layer_.read(buffer, size, error);
}

int CProxySocket::write(void const* buffer, unsigned int size, int& error)
{
	return next_layer_.write(buffer, size, error);
}

std::wstring CProxySocket::GetUser() const
{
	return fz::to_wstring_from_utf8(m_user);
}

std::wstring CProxySocket::GetPass() const
{
	return fz::to_wstring_from_utf8(m_pass);
}

fz::native_string CProxySocket::peer_host() const
{
	return host_;
}

int CProxySocket::peer_port(int& error)  const
{
	if (port_ < 0) {
		error = ENOTCONN;
	}
	return port_;
}
