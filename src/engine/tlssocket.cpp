#include <filezilla.h>

#include "tlssocket.h"
#include "tlssocket_impl.h"

CTlsSocket::CTlsSocket(fz::event_loop& event_loop, fz::event_handler* pEvtHandler, fz::socket_interface & next_layer, fz::tls_system_trust_store* systemTrustStore, CLogging & logger)
	: event_handler(event_loop)
	, fz::socket_layer(pEvtHandler, next_layer, false)
{
	impl_ = std::make_unique<CTlsSocketImpl>(*this, systemTrustStore, logger);
	next_layer.set_event_handler(this);
}

CTlsSocket::~CTlsSocket()
{
	remove_handler();
}

bool CTlsSocket::client_handshake(std::vector<uint8_t> const& session_to_resume, std::vector<uint8_t> const& required_certificate, fz::native_string const& session_hostname)
{
	return impl_->client_handshake(session_to_resume, session_hostname, required_certificate, nullptr);
}

bool CTlsSocket::client_handshake(fz::event_handler* const verification_handler, std::vector<uint8_t> const& session_to_resume, fz::native_string const& session_hostname)
{
	return impl_->client_handshake(session_to_resume, session_hostname, std::vector<uint8_t>(), verification_handler);
}

int CTlsSocket::read(void *buffer, unsigned int size, int& error)
{
	return impl_->read(buffer, size, error);
}

int CTlsSocket::write(void const* buffer, unsigned int size, int& error)
{
	return impl_->write(buffer, size, error);
}

int CTlsSocket::shutdown()
{
	return impl_->shutdown();
}

void CTlsSocket::set_verification_result(bool trusted)
{
	return impl_->set_verification_result(trusted);
}

fz::socket_state CTlsSocket::get_state() const
{
	return impl_->get_state();
}

std::string CTlsSocket::GetProtocolName()
{
	return impl_->GetProtocolName();
}

std::string CTlsSocket::GetKeyExchange()
{
	return impl_->GetKeyExchange();
}

std::string CTlsSocket::GetCipherName()
{
	return impl_->GetCipherName();
}

std::string CTlsSocket::GetMacName()
{
	return impl_->GetMacName();
}

int CTlsSocket::GetAlgorithmWarnings()
{
	return impl_->GetAlgorithmWarnings();
}

bool CTlsSocket::ResumedSession() const
{
	return impl_->ResumedSession();
}

std::string CTlsSocket::ListTlsCiphers(std::string const& priority)
{
	return CTlsSocketImpl::ListTlsCiphers(priority);
}

bool CTlsSocket::SetClientCertificate(fz::native_string const& keyfile, fz::native_string const& certs, fz::native_string const& password)
{
	return impl_->SetClientCertificate(keyfile, certs, password);
}

void CTlsSocket::operator()(fz::event_base const& ev)
{
	return impl_->operator()(ev);
}

std::wstring CTlsSocket::GetGnutlsVersion()
{
	return CTlsSocketImpl::GetGnutlsVersion();
}

std::vector<uint8_t> CTlsSocket::get_session_parameters() const
{
	return impl_->get_session_parameters();
}

std::vector<uint8_t> CTlsSocket::get_raw_certificate() const
{
	return impl_->get_raw_certificate();
}

int CTlsSocket::connect(fz::native_string const& host, unsigned int port, fz::address_type family)
{
	return impl_->connect(host, port, family);
}
