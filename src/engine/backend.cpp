#include <filezilla.h>

#include "backend.h"

SocketLayer::SocketLayer(fz::event_handler* pEvtHandler, fz::socket_interface& next_layer, bool event_passthrough)
	: socket_interface(next_layer.root()) 
	, m_pEvtHandler(pEvtHandler)
	, next_layer_(next_layer)
	, event_passthrough_(event_passthrough)
{
	if (event_passthrough) {
		next_layer_.set_event_handler(pEvtHandler);
	}
}

SocketLayer::~SocketLayer()
{
	remove_socket_events(m_pEvtHandler, this);
	next_layer_.set_event_handler(nullptr);
}

void SocketLayer::set_event_handler(fz::event_handler* pEvtHandler)
{
	auto old = m_pEvtHandler;
	m_pEvtHandler = pEvtHandler;
	fz::change_socket_event_handler(old, pEvtHandler, this);

	if (event_passthrough_) {
		next_layer_.set_event_handler(pEvtHandler);
	}
}

void SocketLayer::forward_socket_event(fz::socket_event_source* source, fz::socket_event_flag t, int error)
{
	if (m_pEvtHandler) {
		(*m_pEvtHandler)(fz::socket_event(source, t, error));
	}
}

void SocketLayer::forward_hostaddress_event(fz::socket_event_source* source, std::string const& address)
{
	if (m_pEvtHandler) {
		(*m_pEvtHandler)(fz::hostaddress_event(source, address));
	}
}

void SocketLayer::set_event_passthrough()
{
	event_passthrough_ = true;
	next_layer_.set_event_handler(m_pEvtHandler);
}

CSocketBackend::CSocketBackend(fz::event_handler* pEvtHandler, fz::socket_interface& next_layer, CRateLimiter& rateLimiter)
	: SocketLayer(pEvtHandler, next_layer, true)
	, m_rateLimiter(rateLimiter)
{
	next_layer_.set_event_handler(pEvtHandler);
	m_rateLimiter.AddObject(this);
}

CSocketBackend::~CSocketBackend()
{
	next_layer_.set_event_handler(nullptr);
	m_rateLimiter.RemoveObject(this);
}

int CSocketBackend::write(const void *buffer, unsigned int len, int& error)
{
	int64_t max = GetAvailableBytes(CRateLimiter::outbound);
	if (max == 0) {
		Wait(CRateLimiter::outbound);
		error = EAGAIN;
		return -1;
	}
	else if (max > 0 && max < len) {
		len = static_cast<unsigned int>(max);
	}

	int written = next_layer_.write(buffer, len, error);

	if (written > 0 && max != -1) {
		UpdateUsage(CRateLimiter::outbound, written);
	}

	return written;
}

int CSocketBackend::read(void *buffer, unsigned int len, int& error)
{
	int64_t max = GetAvailableBytes(CRateLimiter::inbound);
	if (max == 0) {
		Wait(CRateLimiter::inbound);
		error = EAGAIN;
		return -1;
	}
	else if (max > 0 && max < len) {
		len = static_cast<unsigned int>(max);
	}

	int read = next_layer_.read(buffer, len, error);

	if (read > 0 && max != -1) {
		UpdateUsage(CRateLimiter::inbound, read);
	}

	return read;
}

void CSocketBackend::OnRateAvailable(CRateLimiter::rate_direction direction)
{
	if (!m_pEvtHandler) {
		return;
	}

	if (direction == CRateLimiter::outbound) {
		m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::write, 0);
	}
	else {
		m_pEvtHandler->send_event<fz::socket_event>(this, fz::socket_event_flag::read, 0);
	}
}
