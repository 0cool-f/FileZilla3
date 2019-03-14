#ifndef FILEZILLA_ENGINE_PROXY_HEADER
#define FILEZILLA_ENGINE_PROXY_HEADER

#include "backend.h"
#include "socket.h"

#include <libfilezilla/buffer.hpp>

class CControlSocket;
class CProxySocket final : protected fz::event_handler, public SocketLayer
{
public:
	CProxySocket(event_handler* pEvtHandler, fz::socket_interface & next_layer, CControlSocket* pOwner);
	virtual ~CProxySocket();

	enum ProxyState {
		noconn,
		handshake,
		conn
	};

	enum ProxyType {
		unknown,
		HTTP,
		SOCKS5,
		SOCKS4,

		proxytype_count
	};
	static std::wstring Name(ProxyType t);

	int Handshake(ProxyType type, fz::native_string const& host, unsigned int port, std::wstring const& user, std::wstring const& pass);

	ProxyState GetState() const { return m_proxyState; }

	virtual int read(void *buffer, unsigned int size, int& error) override;
	virtual int write(void const* buffer, unsigned int size, int& error) override;

	ProxyType GetProxyType() const { return m_proxyType; }
	std::wstring GetUser() const;
	std::wstring GetPass() const;

	virtual fz::native_string peer_host() const override;
	virtual int peer_port(int& error)  const override;

protected:
	CControlSocket* m_pOwner;

	ProxyType m_proxyType{unknown};
	fz::native_string host_;
	int port_{-1};
	std::string m_user;
	std::string m_pass;

	ProxyState m_proxyState{noconn};

	int m_handshakeState{};

	fz::buffer sendBuffer_;
	fz::buffer receiveBuffer_;

	virtual void operator()(fz::event_base const& ev) override;
	void OnSocketEvent(socket_event_source* source, fz::socket_event_flag t, int error);
	void OnHostAddress(socket_event_source* source, std::string const& address);

	void OnReceive();
	void OnSend();

	bool m_can_write{};
	bool m_can_read{};
};

#endif
