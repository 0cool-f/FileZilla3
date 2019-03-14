#include <filezilla.h>

#include "ControlSocket.h"
#include "tlssocket.h"
#include "tlssocket_impl.h"

CTlsSocket::CTlsSocket(fz::event_handler* pEvtHandler, fz::socket_interface & next_layer, CControlSocket* pOwner)
	: event_handler(pOwner->event_loop_)
	, SocketLayer(pEvtHandler, next_layer, false)
{
	impl_ = std::make_unique<CTlsSocketImpl>(*this, pOwner);
	next_layer.set_event_handler(this);
}

CTlsSocket::~CTlsSocket()
{
	remove_handler();
}

int CTlsSocket::Handshake(CTlsSocket const* pPrimarySocket, bool try_resume)
{
	return impl_->Handshake(pPrimarySocket ? pPrimarySocket->impl_.get() : nullptr, try_resume);
}

int CTlsSocket::read(void *buffer, unsigned int size, int& error)
{
	return impl_->read(buffer, size, error);
}

int CTlsSocket::write(const void *buffer, unsigned int size, int& error)
{
	return impl_->write(buffer, size, error);
}

int CTlsSocket::Shutdown(bool silenceReadErrors)
{
	return impl_->Shutdown(silenceReadErrors);
}

void CTlsSocket::TrustCurrentCert(bool trusted)
{
	return impl_->TrustCurrentCert(trusted);
}

fz::socket_state CTlsSocket::get_state() const
{
	return impl_->get_state();
}

std::wstring CTlsSocket::GetProtocolName()
{
	return impl_->GetProtocolName();
}

std::wstring CTlsSocket::GetKeyExchange()
{
	return impl_->GetKeyExchange();
}

std::wstring CTlsSocket::GetCipherName()
{
	return impl_->GetCipherName();
}

std::wstring CTlsSocket::GetMacName()
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
