#include <filezilla.h>

#include "tlssocket.h"
#include "tlssocket_impl.h"

namespace fz {

tls_layer::tls_layer(event_loop& event_loop, event_handler* evt_handler, socket_interface & next_layer, tls_system_trust_store* system_trust_store, logger_interface & logger)
	: event_handler(event_loop)
	, socket_layer(evt_handler, next_layer, false)
{
	impl_ = std::make_unique<tls_layer_impl>(*this, system_trust_store, logger);
	next_layer.set_event_handler(this);
}

tls_layer::~tls_layer()
{
	remove_handler();
}

bool tls_layer::client_handshake(std::vector<uint8_t> const& session_to_resume, std::vector<uint8_t> const& required_certificate, native_string const& session_hostname)
{
	return impl_->client_handshake(session_to_resume, session_hostname, required_certificate, nullptr);
}

bool tls_layer::client_handshake(event_handler* const verification_handler, std::vector<uint8_t> const& session_to_resume, native_string const& session_hostname)
{
	return impl_->client_handshake(session_to_resume, session_hostname, std::vector<uint8_t>(), verification_handler);
}

int tls_layer::read(void *buffer, unsigned int size, int& error)
{
	return impl_->read(buffer, size, error);
}

int tls_layer::write(void const* buffer, unsigned int size, int& error)
{
	return impl_->write(buffer, size, error);
}

int tls_layer::shutdown()
{
	return impl_->shutdown();
}

void tls_layer::set_verification_result(bool trusted)
{
	return impl_->set_verification_result(trusted);
}

socket_state tls_layer::get_state() const
{
	return impl_->get_state();
}

std::string tls_layer::get_protocol() const
{
	return impl_->get_protocol();
}

std::string tls_layer::get_key_exchange() const
{
	return impl_->get_key_exchange();
}

std::string tls_layer::get_cipher() const
{
	return impl_->get_cipher();
}

std::string tls_layer::get_mac() const
{
	return impl_->get_mac();
}

int tls_layer::get_algorithm_warnings() const
{
	return impl_->get_algorithm_warnings();
}

bool tls_layer::resumed_session() const
{
	return impl_->resumed_session();
}

std::string tls_layer::list_tls_ciphers(std::string const& priority)
{
	return tls_layer_impl::list_tls_ciphers(priority);
}

bool tls_layer::set_client_certificate(native_string const& keyfile, native_string const& certs, native_string const& password)
{
	return impl_->set_client_certificate(keyfile, certs, password);
}

void tls_layer::operator()(event_base const& ev)
{
	return impl_->operator()(ev);
}

std::string tls_layer::get_gnutls_version()
{
	return tls_layer_impl::get_gnutls_version();
}

std::vector<uint8_t> tls_layer::get_session_parameters() const
{
	return impl_->get_session_parameters();
}

std::vector<uint8_t> tls_layer::get_raw_certificate() const
{
	return impl_->get_raw_certificate();
}

int tls_layer::connect(native_string const& host, unsigned int port, address_type family)
{
	return impl_->connect(host, port, family);
}

}