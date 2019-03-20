#ifndef FILEZILLA_ENGINE_BACKEND_HEADER
#define FILEZILLA_ENGINE_BACKEND_HEADER

#include "ratelimiter.h"
#include "socket.h"

class SocketLayer : public fz::socket_interface
{
public:
	explicit SocketLayer(fz::event_handler* pEvtHandler, fz::socket_interface & next_layer, bool event_passthrough);
	virtual ~SocketLayer();

	SocketLayer(SocketLayer const&) = delete;
	SocketLayer& operator=(SocketLayer const&) = delete;

	virtual void set_event_handler(fz::event_handler* pEvtHandler) override;

	virtual fz::native_string peer_host() const override { return next_layer_.peer_host(); }
	virtual int peer_port(int& error) const override { return next_layer_.peer_port(error); }

	socket_interface & next() { return next_layer_; }

protected:
	void forward_socket_event(fz::socket_event_source* source, fz::socket_event_flag t, int error);
	void forward_hostaddress_event(fz::socket_event_source* source, std::string const& address);

	void set_event_passthrough();

	fz::event_handler* m_pEvtHandler;
	fz::socket_interface& next_layer_;
	bool event_passthrough_{};
};

namespace fz {
class CSocket;
}

class CSocketBackend final : public SocketLayer, public CRateLimiterObject
{
public:
	CSocketBackend(fz::event_handler* pEvtHandler, fz::socket_interface& next_layer, CRateLimiter& rateLimiter);
	virtual ~CSocketBackend();

	virtual int read(void *buffer, unsigned int size, int& error) override;
	virtual int write(void const* buffer, unsigned int size, int& error) override;

	virtual fz::socket_state get_state() const override {
		return next_layer_.get_state();
	}

	virtual int connect(fz::native_string const& host, unsigned int port, fz::address_type family = fz::address_type::unknown) override{
		return next_layer_.connect(host, port, family);
	}

	virtual int shutdown() override {
		return next_layer_.shutdown();
	}

protected:
	virtual void OnRateAvailable(CRateLimiter::rate_direction direction) override;

	CRateLimiter& m_rateLimiter;
};

#endif
