#include <filezilla.h>
#include "socket_errors.h"
#include "tlssocket.h"
#include "tlssocket_impl.h"
#include "tls_info.h"
#include "tls_system_trust_store_impl.h"
#include "logging_private.h"

#include <libfilezilla/iputils.hpp>

#include <gnutls/x509.h>

#include <algorithm>

#include <string.h>

static_assert(GNUTLS_VERSION_NUMBER != 0x030604, "Using TLS 1.3 with this version of GnuTLS does not work, update your version of GnuTLS");

namespace fz {

namespace {

#if FZ_USE_GNUTLS_SYSTEM_CIPHERS
char const ciphers[] = "@SYSTEM";
#else
	#if GNUTLS_VERSION_NUMBER >= 0x030600
		char const ciphers[] = "SECURE256:+SECURE128:-ARCFOUR-128:-3DES-CBC:-MD5:+SIGN-ALL:-SIGN-RSA-MD5:+CTYPE-X509:-VERS-SSL3.0";
	#else
		char const ciphers[] = "SECURE256:+SECURE128:-ARCFOUR-128:-3DES-CBC:-MD5:+SIGN-ALL:-SIGN-RSA-MD5:+CTYPE-X509:-CTYPE-OPENPGP:-VERS-SSL3.0";
	#endif
#endif

#define TLSDEBUG 0
#if TLSDEBUG
// This is quite ugly
logger_interface* pLogging;
extern "C" void log_func(int level, char const* msg)
{
	if (!msg || !pLogging) {
		return;
	}
	std::wstring s = to_wstring(msg);
	trim(s);
	pLogging->log(logmsg::debug_debug, L"tls: %d %s", level, s);
}
#endif

void remove_verification_events(event_handler* handler, tls_layer const* const source)
{
	if (!handler) {
		return;
	}

	auto event_filter = [&](event_loop::Events::value_type const& ev) -> bool {
		if (ev.first != handler) {
			return false;
		}
		else if (ev.second->derived_type() == certificate_verification_event::type()) {
			return std::get<0>(static_cast<certificate_verification_event const&>(*ev.second).v_) == source;
		}
		return false;
	};

	handler->event_loop_.filter_events(event_filter);
}

extern "C" ssize_t c_push_function(gnutls_transport_ptr_t ptr, const void* data, size_t len)
{
	return ((tls_layer_impl*)ptr)->push_function(data, len);
}

extern "C" ssize_t c_pull_function(gnutls_transport_ptr_t ptr, void* data, size_t len)
{
	return ((tls_layer_impl*)ptr)->pull_function(data, len);
}
}

class tls_layerCallbacks
{
public:
	static int handshake_hook_func(gnutls_session_t session, unsigned int htype, unsigned int post, unsigned int incoming)
	{
		if (!session) {
			return 0;
		}
		auto* tls = reinterpret_cast<tls_layer_impl*>(gnutls_session_get_ptr(session));
		if (!tls) {
			return 0;
		}

		char const* prefix;
		if (incoming) {
			if (post) {
				prefix = "Processed";
			}
			else {
				prefix = "Received";
			}
		}
		else {
			if (post) {
				prefix = "Sent";
			}
			else {
				prefix = "About to send";
			}
		}

		char const* name = gnutls_handshake_description_get_name(static_cast<gnutls_handshake_description_t>(htype));

		tls->logger_.log(logmsg::debug_debug, L"TLS handshake: %s %s", prefix, name);

		return 0;
	}
};

namespace {
extern "C" int handshake_hook_func(gnutls_session_t session, unsigned int htype, unsigned int post, unsigned int incoming, gnutls_datum_t const*)
{
	return tls_layerCallbacks::handshake_hook_func(session, htype, post, incoming);
}

struct cert_list_holder final
{
	cert_list_holder() = default;
	~cert_list_holder() {
		for (unsigned int i = 0; i < certs_size; ++i) {
			gnutls_x509_crt_deinit(certs[i]);
		}
		gnutls_free(certs);
	}

	cert_list_holder(cert_list_holder const&) = delete;
	cert_list_holder& operator=(cert_list_holder const&) = delete;

	gnutls_x509_crt_t * certs{};
	unsigned int certs_size{};
};

struct datum_holder final : gnutls_datum_t
{
	datum_holder() {
		data = nullptr;
		size = 0;
	}

	~datum_holder() {
		gnutls_free(data);
	}

	void clear()
	{
		gnutls_free(data);
		data = nullptr;
		size = 0;
	}

	datum_holder(datum_holder const&) = delete;
	datum_holder& operator=(datum_holder const&) = delete;

	std::string to_string() const {
		return data ? std::string(data, data + size) : std::string();
	}

	std::string_view to_string_view() const {
		return data ? std::string_view(reinterpret_cast<char *>(data), size) : std::string_view();
	}
};

void clone_cert(gnutls_x509_crt_t in, gnutls_x509_crt_t &out)
{
	gnutls_x509_crt_deinit(out);
	out = nullptr;

	if (in) {
		datum_holder der;
		if (gnutls_x509_crt_export2(in, GNUTLS_X509_FMT_DER, &der) == GNUTLS_E_SUCCESS) {
			gnutls_x509_crt_init(&out);
			if (gnutls_x509_crt_import(out, &der, GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS) {
				gnutls_x509_crt_deinit(out);
				out = nullptr;
			}
		}
	}
}
}

tls_layer_impl::tls_layer_impl(tls_layer& layer, tls_system_trust_store* systemTrustStore, logger_interface & logger)
	: tls_layer_(layer)
	, logger_(logger)
	, system_trust_store_(systemTrustStore)
{
}

tls_layer_impl::~tls_layer_impl()
{
	deinit();
}

bool tls_layer_impl::init()
{
	// This function initializes GnuTLS
	if (!initialized_) {
		initialized_ = true;
		int res = gnutls_global_init();
		if (res) {
			log_error(res, L"gnutls_global_init");
			deinit();
			return false;
		}

#if TLSDEBUG
		if (!pLogging) {
			pLogging = &logger_;
			gnutls_global_set_log_function(log_func);
			gnutls_global_set_log_level(99);
		}
#endif
	}

	if (!cert_credentials_) {
		int res = gnutls_certificate_allocate_credentials(&cert_credentials_);
		if (res < 0) {
			log_error(res, L"gnutls_certificate_allocate_credentials");
			deinit();
			return false;
		}
	}

	return true;
}

bool tls_layer_impl::set_client_certificate(native_string const& keyfile, native_string const& certs, native_string const& password)
{
	if (!init()) {
		return false;
	}

	if (!cert_credentials_) {
		return false;
	}

	int res = gnutls_certificate_set_x509_key_file2(cert_credentials_, to_string(certs).c_str(),
		to_string(keyfile).c_str(), GNUTLS_X509_FMT_PEM, password.empty() ? nullptr : to_utf8(password).c_str(), 0);
	if (res < 0) {
		log_error(res, L"gnutls_certificate_set_x509_key_file2");
		deinit();
		return false;
	}

	return true;
}

bool tls_layer_impl::init_session()
{
	if (!cert_credentials_) {
		deinit();
		return false;
	}

	int res = gnutls_init(&session_, GNUTLS_CLIENT);
	if (res) {
		log_error(res, L"gnutls_init");
		deinit();
		return false;
	}

	// For use in callbacks
	gnutls_session_set_ptr(session_, this);

	// Even though the name gnutls_db_set_cache_expiration
	// implies expiration of some cache, it also governs
	// the actual session lifetime, independend whether the
	// session is cached or not.
	gnutls_db_set_cache_expiration(session_, 100000000);

	res = gnutls_priority_set_direct(session_, ciphers, nullptr);
	if (res) {
		log_error(res, L"gnutls_priority_set_direct");
		deinit();
		return false;
	}

	gnutls_dh_set_prime_bits(session_, 1024);

	gnutls_credentials_set(session_, GNUTLS_CRD_CERTIFICATE, cert_credentials_);

	// Setup transport functions
	gnutls_transport_set_push_function(session_, c_push_function);
	gnutls_transport_set_pull_function(session_, c_pull_function);
	gnutls_transport_set_ptr(session_, (gnutls_transport_ptr_t)this);

	return true;
}

void tls_layer_impl::deinit()
{
	deinit_session();

	if (cert_credentials_) {
		gnutls_certificate_free_credentials(cert_credentials_);
		cert_credentials_ = nullptr;
	}

	if (initialized_) {
		initialized_ = false;
		gnutls_global_deinit();
	}

	state_ = socket_state::failed;

#if TLSDEBUG
	if (pLogging == &logger_) {
		pLogging = nullptr;
	}
#endif

	remove_verification_events(verification_handler_, &tls_layer_);
	verification_handler_ = nullptr;
}


void tls_layer_impl::deinit_session()
{
	if (session_) {
		gnutls_deinit(session_);
		session_ = nullptr;
	}
}


void tls_layer_impl::log_error(int code, std::wstring const& function, logmsg::type logLevel)
{
	if (logLevel < logmsg::debug_warning && state_ >= socket_state::shut_down && shutdown_silence_read_errors_) {
		logLevel = logmsg::debug_warning;
	}

	if (code == GNUTLS_E_WARNING_ALERT_RECEIVED || code == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		log_alert(logLevel);
	}
	else if (code == GNUTLS_E_PULL_ERROR) {
		if (function.empty()) {
			logger_.log(logmsg::debug_warning, L"GnuTLS could not read from socket: %s", socket_error_description(socket_error_));
		}
		else {
			logger_.log(logmsg::debug_warning, L"GnuTLS could not read from socket in %s: %s", function, socket_error_description(socket_error_));
		}
	}
	else if (code == GNUTLS_E_PUSH_ERROR) {
		if (function.empty()) {
			logger_.log(logmsg::debug_warning, L"GnuTLS could not write to socket: %s", socket_error_description(socket_error_));
		}
		else {
			logger_.log(logmsg::debug_warning, L"GnuTLS could not write to socket in %s: %s", function, socket_error_description(socket_error_));
		}
	}
	else {
		char const* error = gnutls_strerror(code);
		if (error) {
			if (function.empty()) {
				logger_.log(logLevel, _("GnuTLS error %d: %s"), code, error);
			}
			else {
				logger_.log(logLevel, _("GnuTLS error %d in %s: %s"), code, function, error);
			}
		}
		else {
			if (function.empty()) {
				logger_.log(logLevel, _("GnuTLS error %d"), code);
			}
			else {
				logger_.log(logLevel, _("GnuTLS error %d in %s"), code, function);
			}
		}
	}
}

void tls_layer_impl::log_alert(logmsg::type logLevel)
{
	gnutls_alert_description_t last_alert = gnutls_alert_get(session_);
	char const* alert = gnutls_alert_get_name(last_alert);
	if (alert) {
		logger_.log(logLevel, _("Received TLS alert from the server: %s (%d)"), alert, last_alert);
	}
	else {
		logger_.log(logLevel, _("Received unknown TLS alert %d from the server"), last_alert);
	}
}

ssize_t tls_layer_impl::push_function(void const* data, size_t len)
{
#if TLSDEBUG
	logger_.log(logmsg::debug_debug, L"tls_layer_impl::push_function(%d)", len);
#endif
	if (!can_write_to_socket_) {
		gnutls_transport_set_errno(session_, EAGAIN);
		return -1;
	}

	int error;
	int written = tls_layer_.next_layer_.write(data, static_cast<unsigned int>(len), error);

	if (written < 0) {
		can_write_to_socket_ = false;
		if (error == EAGAIN) {
			socket_error_ = error;
		}
		gnutls_transport_set_errno(session_, error);
#if TLSDEBUG
		logger_.log(logmsg::debug_debug, L"  returning -1 due to %d", error);
#endif
		return -1;
	}

#if TLSDEBUG
	logger_.log(logmsg::debug_debug, L"  returning %d", written);
#endif

	return written;
}

ssize_t tls_layer_impl::pull_function(void* data, size_t len)
{
#if TLSDEBUG
	logger_.log(logmsg::debug_debug, L"tls_layer_impl::pull_function(%d)",  (int)len);
#endif

	if (!can_read_from_socket_) {
		gnutls_transport_set_errno(session_, EAGAIN);
		return -1;
	}

	int error;
	int read = tls_layer_.next_layer_.read(data, static_cast<unsigned int>(len), error);
	if (read < 0) {
		can_read_from_socket_ = false;
		if (error != EAGAIN) {
			socket_error_ = error;
		}
		gnutls_transport_set_errno(session_, error);
#if TLSDEBUG
		logger_.log(logmsg::debug_debug, L"  returning -1 due to %d", error);
#endif
		return -1;
	}

	if (!read) {
		socket_eof_ = true;
	}

#if TLSDEBUG
	logger_.log(logmsg::debug_debug, L"  returning %d", read);
#endif

	return read;
}

void tls_layer_impl::operator()(event_base const& ev)
{
	dispatch<socket_event, hostaddress_event>(ev, this
		, &tls_layer_impl::on_socket_event
		, &tls_layer_impl::forward_hostaddress_event);
}

void tls_layer_impl::forward_hostaddress_event(socket_event_source* source, std::string const& address)
{
	tls_layer_.forward_hostaddress_event(source, address);
}

void tls_layer_impl::on_socket_event(socket_event_source* s, socket_event_flag t, int error)
{
	if (!session_) {
		return;
	}

	if (t == socket_event_flag::connection_next) {
		tls_layer_.forward_socket_event(s, t, error);
		return;
	}

	if (error) {
		socket_error_ = error;
		deinit();
		tls_layer_.forward_socket_event(s, t, error);
		return;
	}

	switch (t)
	{
	case socket_event_flag::read:
		on_read();
		break;
	case socket_event_flag::write:
		on_send();
		break;
	case socket_event_flag::connection:
		if (hostname_.empty()) {
			set_hostname(tls_layer_.next_layer_.peer_host());
		}
	default:
		break;
	}
}

void tls_layer_impl::on_read()
{
	logger_.log(logmsg::debug_debug, L"tls_layer_impl::on_read()");

	can_read_from_socket_ = true;

	if (!session_) {
		return;
	}

	if (state_ == socket_state::connecting) {
		continue_handshake();
	}
	else if (state_ == socket_state::connected || state_ == socket_state::shutting_down || state_ == socket_state::shut_down) {
		if (tls_layer_.event_handler_) {
			tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::read, 0);
		}
	}
}

void tls_layer_impl::on_send()
{
	logger_.log(logmsg::debug_debug, L"tls_layer_impl::on_send()");

	can_write_to_socket_ = true;

	if (!session_) {
		return;
	}

	if (state_ == socket_state::connecting) {
		continue_handshake();
	}
	else if (state_ == socket_state::shutting_down) {
		int res = continue_shutdown();
		if (res != EAGAIN) {
			if (tls_layer_.event_handler_) {
				tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::write, res);
			}
		}
	}
	else if (state_ == socket_state::connected) {
		continue_write();
	}
}

void tls_layer_impl::continue_write()
{
	if (last_write_failed_) {
		ssize_t res = GNUTLS_E_AGAIN;
		while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && can_write_to_socket_) {
			res = gnutls_record_send(session_, nullptr, 0);
		}

		if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
			return;
		}

		if (res < 0) {
			failure(static_cast<int>(res), true);
			return;
		}

		write_skip_ += static_cast<int>(res);
		last_write_failed_ = false;
		if (tls_layer_.event_handler_) {
			tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::write, 0);
		}
	}
}

bool tls_layer_impl::resumed_session() const
{
	return gnutls_session_is_resumed(session_) != 0;
}

bool tls_layer_impl::client_handshake(std::vector<uint8_t> const& session_to_resume, native_string const& session_hostname, std::vector<uint8_t> const& required_certificate, event_handler *const verification_handler)
{
	logger_.log(logmsg::debug_verbose, L"tls_layer_impl::client_handshake()");

	if (state_ != socket_state::none) {
		logger_.log(logmsg::debug_warning, L"Called tls_layer_impl::client_handshake on a socket that isn't idle");
		return false;
	}

	if (!init() || !init_session()) {
		return false;
	}

	state_ = socket_state::connecting;

	required_certificate_ = required_certificate;
	verification_handler_ = verification_handler;

	if (!session_to_resume.empty()) {
		int res = gnutls_session_set_data(session_, session_to_resume.data(), session_to_resume.size());
		if (res) {
			logger_.log(logmsg::debug_info, L"gnutls_session_set_data failed: %d. Going to reinitialize session.", res);
			deinit_session();
			if (!init_session()) {
				return false;
			}
		}
		else {
			logger_.log(logmsg::debug_info, L"Trying to resume existing TLS session.");
		}
	}

	if (logger_.should_log(logmsg::debug_debug)) {
		gnutls_handshake_set_hook_function(session_, GNUTLS_HANDSHAKE_ANY, GNUTLS_HOOK_BOTH, &handshake_hook_func);
	}

	if (!session_hostname.empty()) {
		set_hostname(session_hostname);
	}

	if (tls_layer_.next_layer_.get_state() != socket_state::connected) {
		return true;
	}

	if (hostname_.empty()) {
		set_hostname(tls_layer_.next_layer_.peer_host());
	}
	return continue_handshake() == EAGAIN;
}

int tls_layer_impl::continue_handshake()
{
	logger_.log(logmsg::debug_verbose, L"tls_layer_impl::continue_handshake()");
	assert(session_);
	assert(state_ == socket_state::connecting);

	int res = gnutls_handshake(session_);
	while (res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) {
		if (!(gnutls_record_get_direction(session_) ? can_write_to_socket_ : can_read_from_socket_)) {
			break;
		}
		res = gnutls_handshake(session_);
	}
	if (!res) {
		logger_.log(logmsg::debug_info, L"TLS Handshake successful");
		handshake_successful_ = true;

		if (resumed_session()) {
			logger_.log(logmsg::debug_info, L"TLS Session resumed");
		}

		std::string const protocol = get_protocol();
		std::string const keyExchange = get_key_exchange();
		std::string const cipherName = get_cipher();
		std::string const macName = get_mac();

		logger_.log(logmsg::debug_info, L"Protocol: %s, Key exchange: %s, Cipher: %s, MAC: %s", protocol, keyExchange, cipherName, macName);

		return verify_certificate();
	}
	else if (res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) {
		return EAGAIN;
	}

	failure(res, true);

	return socket_error_ ? socket_error_ : ECONNABORTED;
}

int tls_layer_impl::read(void *buffer, unsigned int len, int& error)
{
	if (state_ == socket_state::connecting) {
		error = EAGAIN;
		return -1;
	}
	else if (state_ != socket_state::connected && state_ != socket_state::shutting_down && state_ != socket_state::shut_down) {
		error = ENOTCONN;
		return -1;
	}

	int res = do_call_gnutls_record_recv(buffer, len);
	if (res >= 0) {
		if (!res) {
			// Peer did already initiate a shutdown, reply to it
			gnutls_bye(session_, GNUTLS_SHUT_WR);
			// Note: Theoretically this could return a write error.
			// But we ignore it, since it is perfectly valid for peer
			// to close the connection after sending its shutdown
			// notification.
		}
		error = 0;
		return res;
	}

	if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
		error = EAGAIN;
	}
	else {
		failure(res, false, L"gnutls_record_recv");
		error = socket_error_;
	}

	return -1;
}

int tls_layer_impl::write(void const* buffer, unsigned int len, int& error)
{
	if (state_ == socket_state::connecting) {
		error = EAGAIN;
		return -1;
	}
	else if (state_ == socket_state::shutting_down || state_ == socket_state::shut_down) {
		error = ESHUTDOWN;
		return -1;
	}
	else if (state_ != socket_state::connected) {
		error = ENOTCONN;
		return -1;
	}

	if (last_write_failed_) {
		error = EAGAIN;
		return -1;
	}

	if (write_skip_ >= len) {
		write_skip_ -= len;
		return len;
	}

	len -= write_skip_;
	buffer = (char*)buffer + write_skip_;

	ssize_t res = gnutls_record_send(session_, buffer, len);

	while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && can_write_to_socket_) {
		res = gnutls_record_send(session_, nullptr, 0);
	}

	if (res >= 0) {
		error = 0;
		int written = static_cast<int>(res) + write_skip_;
		write_skip_ = 0;
		return written;
	}

	if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
		if (write_skip_) {
			error = 0;
			int written = write_skip_;
			write_skip_ = 0;
			return written;
		}
		else {
			error = EAGAIN;
			last_write_failed_ = true;
			return -1;
		}
	}
	else {
		failure(static_cast<int>(res), false, L"gnutls_record_send");
		error = socket_error_;
		return -1;
	}
}

void tls_layer_impl::failure(int code, bool send_close, std::wstring const& function)
{
	logger_.log(logmsg::debug_debug, L"tls_layer_impl::failure(%d)", code);
	if (code) {
		log_error(code, function);
		if (socket_eof_) {
			if (code == GNUTLS_E_UNEXPECTED_PACKET_LENGTH
#ifdef GNUTLS_E_PREMATURE_TERMINATION
				|| code == GNUTLS_E_PREMATURE_TERMINATION
#endif
				)
			{
				if (state_ != socket_state::shut_down || !shutdown_silence_read_errors_) {
					logger_.log(logmsg::status, _("Server did not properly shut down TLS connection"));
				}
			}
		}
	}

	auto const oldState = state_;

	deinit();

	if (send_close && tls_layer_.event_handler_) {
		int error = socket_error_;
		if (!error) {
			error = ECONNABORTED;
		}
		if (oldState == socket_state::connecting) {
			tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::connection, error);
		}
		else {
			tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::read, error);
		}
	}
}

int tls_layer_impl::shutdown()
{
	logger_.log(logmsg::debug_verbose, L"tls_layer_impl::Shutdown()");

	if (state_ == socket_state::shut_down) {
		return 0;
	}
	else if (state_ == socket_state::shutting_down) {
		return EAGAIN;
	}
	else if (state_ != socket_state::connected) {
		return ENOTCONN;
	}

	state_ = socket_state::shutting_down;

	return continue_shutdown();
}

int tls_layer_impl::continue_shutdown()
{
	logger_.log(logmsg::debug_verbose, L"tls_layer_impl::continue_shutdown()");

	if (!sent_closure_alert_) {
		int res = gnutls_bye(session_, GNUTLS_SHUT_WR);
		while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && can_write_to_socket_) {
			res = gnutls_bye(session_, GNUTLS_SHUT_WR);
		}
		if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
			return EAGAIN;
		}
		else if (res) {
			failure(res, false, L"gnutls_bye");
			return socket_error_ ? socket_error_ : ECONNABORTED;
		}
		sent_closure_alert_ = true;
	}
	
	int res = tls_layer_.next_layer_.shutdown();
	if (res == EAGAIN) {
		return EAGAIN;
	}

	if (!res) {
		state_ = socket_state::shut_down;
	}
	else {
		socket_error_ = res;
		failure(0, false);
	}
	return res;
}

void tls_layer_impl::set_verification_result(bool trusted)
{
	if (state_ != socket_state::connecting && !handshake_successful_) {
		logger_.log(logmsg::debug_warning, L"TrustCurrentCert called at wrong time.");
		return;
	}

	remove_verification_events(verification_handler_, &tls_layer_);
	verification_handler_ = nullptr;

	if (trusted) {
		state_ = socket_state::connected;

		if (tls_layer_.event_handler_) {
			tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::connection, 0);
			if (can_read_from_socket_) {
				tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::read, 0);
			}
			if (can_write_to_socket_) {
				tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::write, 0);
			}
		}

		return;
	}

	logger_.log(logmsg::error, _("Remote certificate not trusted."));
	failure(0, true);
}

static std::string bin2hex(unsigned char const* in, size_t size)
{
	std::string str;
	str.reserve(size * 3);
	for (size_t i = 0; i < size; ++i) {
		if (i) {
			str += ':';
		}
		str += int_to_hex_char<char>(in[i] >> 4);
		str += int_to_hex_char<char>(in[i] & 0xf);
	}

	return str;
}


bool tls_layer_impl::extract_cert(gnutls_x509_crt_t const& cert, x509_certificate& out)
{
	datetime expiration_time(gnutls_x509_crt_get_expiration_time(cert), datetime::seconds);
	datetime activation_time(gnutls_x509_crt_get_activation_time(cert), datetime::seconds);

	// Get the serial number of the certificate
	unsigned char buffer[40];
	size_t size = sizeof(buffer);
	int res = gnutls_x509_crt_get_serial(cert, buffer, &size);
	if (res != 0) {
		size = 0;
	}

	auto serial = bin2hex(buffer, size);

	unsigned int pkBits;
	int pkAlgo = gnutls_x509_crt_get_pk_algorithm(cert, &pkBits);
	std::string pkAlgoName;
	if (pkAlgo >= 0) {
		char const* pAlgo = gnutls_pk_algorithm_get_name((gnutls_pk_algorithm_t)pkAlgo);
		if (pAlgo) {
			pkAlgoName = pAlgo;
		}
	}

	int signAlgo = gnutls_x509_crt_get_signature_algorithm(cert);
	std::string signAlgoName;
	if (signAlgo >= 0) {
		char const* pAlgo = gnutls_sign_algorithm_get_name((gnutls_sign_algorithm_t)signAlgo);
		if (pAlgo) {
			signAlgoName = pAlgo;
		}
	}

	std::string subject, issuer;

	datum_holder raw_subject;
	if (!gnutls_x509_crt_get_dn3(cert, &raw_subject, 0)) {
		subject = raw_subject.to_string_view();
	}
	else {
		log_error(res, L"gnutls_x509_crt_get_dn3");
	}
	if (subject.empty()) {
		logger_.log(logmsg::error, _("Could not get distinguished name of certificate subject, gnutls_x509_get_dn failed"));
		return false;
	}

	std::vector<x509_certificate::SubjectName> alt_subject_names = get_cert_subject_alt_names(cert);

	datum_holder raw_issuer;
	if (!gnutls_x509_crt_get_issuer_dn3(cert, &raw_issuer, 0)) {
		issuer = raw_issuer.to_string_view();
	}
	else {
		log_error(res, L"gnutls_x509_crt_get_issuer_dn3");
	}
	if (issuer.empty() ) {
		logger_.log(logmsg::error, _("Could not get distinguished name of certificate issuer, gnutls_x509_get_issuer_dn failed"));
		return false;
	}

	std::string fingerprint_sha256;
	std::string fingerprint_sha1;

	unsigned char digest[100];
	size = sizeof(digest) - 1;
	if (!gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA256, digest, &size)) {
		digest[size] = 0;
		fingerprint_sha256 = bin2hex(digest, size);
	}
	size = sizeof(digest) - 1;
	if (!gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA1, digest, &size)) {
		digest[size] = 0;
		fingerprint_sha1 = bin2hex(digest, size);
	}

	datum_holder der;
	if (gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_DER, &der) != GNUTLS_E_SUCCESS || !der.data || !der.size) {
		logger_.log(logmsg::error, L"gnutls_x509_crt_get_issuer_dn");
		return false;
	}
	std::vector<uint8_t> data(der.data, der.data + der.size);

	out = x509_certificate(
		std::move(data),
		activation_time, expiration_time,
		serial,
		pkAlgoName, pkBits,
		signAlgoName,
		fingerprint_sha256,
		fingerprint_sha1,
		issuer,
		subject,
		std::move(alt_subject_names));

	return true;
}


std::vector<x509_certificate::SubjectName> tls_layer_impl::get_cert_subject_alt_names(gnutls_x509_crt_t cert)
{
	std::vector<x509_certificate::SubjectName> ret;

	char san[4096];
	for (unsigned int i = 0; i < 10000; ++i) { // I assume this is a sane limit
		size_t san_size = sizeof(san) - 1;
		int const type_or_error = gnutls_x509_crt_get_subject_alt_name(cert, i, san, &san_size, nullptr);
		if (type_or_error == GNUTLS_E_SHORT_MEMORY_BUFFER) {
			continue;
		}
		else if (type_or_error < 0) {
			break;
		}

		if (type_or_error == GNUTLS_SAN_DNSNAME || type_or_error == GNUTLS_SAN_RFC822NAME) {
			std::string dns = san;
			if (!dns.empty()) {
				ret.emplace_back(x509_certificate::SubjectName{std::move(dns), type_or_error == GNUTLS_SAN_DNSNAME});
			}
		}
		else if (type_or_error == GNUTLS_SAN_IPADDRESS) {
			std::string ip = socket::address_to_string(san, static_cast<int>(san_size));
			if (!ip.empty()) {
				ret.emplace_back(x509_certificate::SubjectName{std::move(ip), false});
			}
		}
	}
	return ret;
}

bool tls_layer_impl::certificate_is_blacklisted(std::vector<x509_certificate> const&)
{
	return false;
}


int tls_layer_impl::get_algorithm_warnings() const
{
	int algorithmWarnings{};

	switch (gnutls_protocol_get_version(session_))
	{
		case GNUTLS_SSL3:
		case GNUTLS_VERSION_UNKNOWN:
			algorithmWarnings |= tls_session_info::tlsver;
			break;
		default:
			break;
	}

	switch (gnutls_cipher_get(session_)) {
		case GNUTLS_CIPHER_UNKNOWN:
		case GNUTLS_CIPHER_NULL:
		case GNUTLS_CIPHER_ARCFOUR_128:
		case GNUTLS_CIPHER_3DES_CBC:
		case GNUTLS_CIPHER_ARCFOUR_40:
		case GNUTLS_CIPHER_RC2_40_CBC:
		case GNUTLS_CIPHER_DES_CBC:
			algorithmWarnings |= tls_session_info::cipher;
			break;
		default:
			break;
	}

	switch (gnutls_mac_get(session_)) {
		case GNUTLS_MAC_UNKNOWN:
		case GNUTLS_MAC_NULL:
		case GNUTLS_MAC_MD5:
		case GNUTLS_MAC_MD2:
		case GNUTLS_MAC_UMAC_96:
			algorithmWarnings |= tls_session_info::mac;
			break;
		default:
			break;
	}

	switch (gnutls_kx_get(session_)) {
		case GNUTLS_KX_UNKNOWN:
		case GNUTLS_KX_ANON_DH:
		case GNUTLS_KX_RSA_EXPORT:
		case GNUTLS_KX_ANON_ECDH:
			algorithmWarnings |= tls_session_info::kex;
		default:
			break;
	}

	return algorithmWarnings;
}


bool tls_layer_impl::get_sorted_peer_certificates(gnutls_x509_crt_t *& certs, unsigned int & certs_size)
{
	certs = nullptr;
	certs_size = 0;

	// First get unsorted list of peer certificates in DER
	unsigned int cert_list_size;
	const gnutls_datum_t* cert_list = gnutls_certificate_get_peers(session_, &cert_list_size);
	if (!cert_list || !cert_list_size) {
		logger_.log(logmsg::error, _("gnutls_certificate_get_peers returned no certificates"));
		return false;
	}

	// Convert them all to PEM
	gnutls_datum_t *pem_cert_list = new gnutls_datum_t[cert_list_size];
	for (unsigned i = 0; i < cert_list_size; ++i) {
		if (gnutls_pem_base64_encode2("CERTIFICATE", cert_list + i, pem_cert_list + i) != 0) {
			for (unsigned int j = 0; j < i; ++j) {
				gnutls_free(pem_cert_list[j].data);
			}
			delete [] pem_cert_list;
			logger_.log(logmsg::error, _("gnutls_pem_base64_encode2 failed"));
			return false;
		}
	}

	// Concatenate them
	gnutls_datum_t concated_certs{};
	for (unsigned i = 0; i < cert_list_size; ++i) {
		concated_certs.size += pem_cert_list[i].size;
	}
	concated_certs.data = new unsigned char[concated_certs.size];
	concated_certs.size = 0;
	for (unsigned i = 0; i < cert_list_size; ++i) {
		memcpy(concated_certs.data + concated_certs.size, pem_cert_list[i].data, pem_cert_list[i].size);
		concated_certs.size += pem_cert_list[i].size;
	}

	for (unsigned i = 0; i < cert_list_size; ++i) {
		gnutls_free(pem_cert_list[i].data);
	}
	delete[] pem_cert_list;

	// And now import the certificates
	int res = gnutls_x509_crt_list_import2(&certs, &certs_size, &concated_certs, GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED);
	if (res == GNUTLS_E_CERTIFICATE_LIST_UNSORTED) {
		logger_.log(logmsg::error, _("Server sent unsorted certificate chain in violation of the TLS specifications"));
		res = gnutls_x509_crt_list_import2(&certs, &certs_size, &concated_certs, GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_SORT);
	}

	delete[] concated_certs.data;

	if (res != GNUTLS_E_SUCCESS) {
		certs = nullptr;
		certs_size = 0;
		logger_.log(logmsg::error, _("Could not sort peer certificates"));
		return false;
	}

	return true;
}

void tls_layer_impl::log_verification_error(int status)
{
	gnutls_datum_t buffer{};
	gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509, &buffer, 0);
	if (buffer.data) {
		logger_.log(logmsg::debug_warning, L"Gnutls Verification status: %s", buffer.data);
		gnutls_free(buffer.data);
	}

	if (status & GNUTLS_CERT_REVOKED) {
		logger_.log(logmsg::error, _("Beware! Certificate has been revoked"));

		// The remaining errors are no longer of interest
		return;
	}
	if (status & GNUTLS_CERT_SIGNATURE_FAILURE) {
		logger_.log(logmsg::error, _("Certificate signature verification failed"));
		status &= ~GNUTLS_CERT_SIGNATURE_FAILURE;
	}
	if (status & GNUTLS_CERT_INSECURE_ALGORITHM) {
		logger_.log(logmsg::error, _("A certificate in the chain was signed using an insecure algorithm"));
		status &= ~GNUTLS_CERT_INSECURE_ALGORITHM;
	}
	if (status & GNUTLS_CERT_SIGNER_NOT_CA) {
		logger_.log(logmsg::error, _("An issuer in the certificate chain is not a certificate authority"));
		status &= ~GNUTLS_CERT_SIGNER_NOT_CA;
	}
	if (status & GNUTLS_CERT_UNEXPECTED_OWNER) {
		logger_.log(logmsg::error, _("The server's hostname does not match the certificate's hostname"));
		status &= ~GNUTLS_CERT_UNEXPECTED_OWNER;
	}
#ifdef GNUTLS_CERT_MISSING_OCSP_STATUS
	if (status & GNUTLS_CERT_MISSING_OCSP_STATUS) {
		logger_.log(logmsg::error, _("The certificate requires the server to include an OCSP status in its response, but the OCSP status is missing."));
		status &= ~GNUTLS_CERT_MISSING_OCSP_STATUS;
	}
#endif
	if (status) {
		logger_.log(logmsg::error, _("Received certificate chain could not be verified. Verification status is %d."), status);
	}

}

int tls_layer_impl::verify_certificate()
{
	if (state_ != socket_state::connecting) {
		logger_.log(logmsg::debug_warning, L"verify_certificate called at wrong time");
		return ENOTCONN;
	}

	if (gnutls_certificate_type_get(session_) != GNUTLS_CRT_X509) {
		logger_.log(logmsg::error, _("Unsupported certificate type"));
		failure(0, true);
		return EOPNOTSUPP;
	}

	cert_list_holder certs;
	if (!get_sorted_peer_certificates(certs.certs, certs.certs_size)) {
		failure(0, true);
		return EINVAL;
	}

	datum_holder cert_der{};
	int res = gnutls_x509_crt_export2(certs.certs[0], GNUTLS_X509_FMT_DER, &cert_der);
	if (res != GNUTLS_E_SUCCESS) {
		failure(res, true, L"gnutls_x509_crt_export2");
		return ECONNABORTED;
	}

	if (!required_certificate_.empty()) {
		if (required_certificate_.size() != cert_der.size ||
			memcmp(required_certificate_.data(), cert_der.data, cert_der.size))
		{
			logger_.log(logmsg::error, _("Certificate of connection does not match expected certificate."));
			failure(0, true);
			return EINVAL;
		}

		set_verification_result(true);

		if (state_ != socket_state::connected && state_ != socket_state::shutting_down && state_ != socket_state::shut_down) {
			return ECONNABORTED;
		}
		return 0;
	}

	bool const uses_hostname = !hostname_.empty() && get_address_type(hostname_) == address_type::unknown;

	bool systemTrust = false;
	bool hostnameMismatch = false;

	// Our trust-model is user-guided TOFU on the host's certificate.
	// 
	// First we verify it against the system trust store.
	//
	// If that fails, we validate the certificate chain sent by the server
	// allowing three impairments:
	// - Hostname mismatch
	// - Out of validity
	// - Signer not found
	//
	// In any case, actual trust decision is done later by the user.


	// First, check system trust
	if (uses_hostname && system_trust_store_) {

		auto lease = system_trust_store_->impl_->lease();
		auto cred = std::get<0>(lease);
		if (cred) {
			gnutls_credentials_set(session_, GNUTLS_CRD_CERTIFICATE, cred);
			unsigned int status = 0;
			int verifyResult = gnutls_certificate_verify_peers3(session_, to_utf8(hostname_).c_str(), &status);
			gnutls_credentials_set(session_, GNUTLS_CRD_CERTIFICATE, cert_credentials_);
			std::get<1>(lease).unlock();

			if (verifyResult < 0) {
				logger_.log(logmsg::debug_warning, L"gnutls_certificate_verify_peers2 returned %d with status %u", verifyResult, status);
				logger_.log(logmsg::error, _("Failed to verify peer certificate"));
				failure(0, true);
				return EINVAL;
			}

			if (!status) {
				systemTrust = true;
			}
		}
		else {
			std::get<1>(lease).unlock();
			logger_.log(logmsg::debug_warning, L"System trust store could not be loaded");
		}
	}

	if (!verification_handler_) {
		set_verification_result(systemTrust);
		return systemTrust ? 0 : ECONNABORTED;
	}
	else {
		if (!systemTrust) {
			// System trust store cannot verify this certificate. Allow three impairments:
			//
			// 1. For now, add the highest certificate from the chain to trust list. Otherwise
			// gnutls_certificate_verify_peers2 always stops with GNUTLS_CERT_SIGNER_NOT_FOUND
			// at the highest certificate in the chain.
			gnutls_x509_crt_t root{};
			clone_cert(certs.certs[certs.certs_size - 1], root);
			if (!root) {
				logger_.log(logmsg::error, _("Could not copy certificate"));
				failure(0, true);
				return ECONNABORTED;
			}

			gnutls_x509_trust_list_t tlist;
			gnutls_certificate_get_trust_list(cert_credentials_, &tlist);
			if (gnutls_x509_trust_list_add_cas(tlist, &root, 1, 0) != 1) {
				logger_.log(logmsg::error, _("Could not add certificate to temporary trust list"));
				failure(0, true);
				return ECONNABORTED;
			}

			// 2. Also disable time checks. We allow expired/not yet valid certificates, though only
			// after explicit user confirmation.
			gnutls_certificate_set_verify_flags(cert_credentials_, gnutls_certificate_get_verify_flags(cert_credentials_) | GNUTLS_VERIFY_DISABLE_TIME_CHECKS | GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS);

			unsigned int status = 0;
			int verifyResult = gnutls_certificate_verify_peers2(session_, &status);

			if (verifyResult < 0) {
				logger_.log(logmsg::debug_warning, L"gnutls_certificate_verify_peers2 returned %d with status %u", verifyResult, status);
				logger_.log(logmsg::error, _("Failed to verify peer certificate"));
				failure(0, true);
				return EINVAL;
			}

			if (status != 0) {
				log_verification_error(status);

				failure(0, true);
				return EINVAL;
			}

			// 3. Hostname mismatch
			if (uses_hostname) {
				if (!gnutls_x509_crt_check_hostname(certs.certs[0], to_utf8(hostname_).c_str())) {
					hostnameMismatch = true;
					logger_.log(logmsg::debug_warning, L"Hostname does not match certificate SANs");
				}
			}
		}

		logger_.log(logmsg::status, _("Verifying certificate..."));

		std::vector<x509_certificate> certificates;
		certificates.reserve(certs.certs_size);
		for (unsigned int i = 0; i < certs.certs_size; ++i) {
			x509_certificate cert;
			if (extract_cert(certs.certs[i], cert)) {
				certificates.push_back(cert);
			}
			else {
				failure(0, true);
				return ECONNABORTED;
			}
		}

		if (certificate_is_blacklisted(certificates)) {
			failure(0, true);
			return EINVAL;
		}

		int const algorithmWarnings = get_algorithm_warnings();

		int error;
		auto port = tls_layer_.peer_port(error);
		if (port == -1) {
			socket_error_ = error;
			failure(0, true);
			return ECONNABORTED;
		}

		tls_session_info session_info(
			to_utf8(to_wstring(hostname_)),
			port,
			get_protocol(),
			get_key_exchange(),
			get_cipher(),
			get_mac(),
			algorithmWarnings,
			std::move(certificates),
			systemTrust,
			hostnameMismatch
		);

		verification_handler_->send_event<certificate_verification_event>(&tls_layer_, std::move(session_info));

		return EAGAIN;
	}
}

std::string tls_layer_impl::get_protocol() const
{
	std::string ret;

	char const* s = gnutls_protocol_get_name(gnutls_protocol_get_version(session_));
	if (s && *s) {
		ret = s;
	}

	if (ret.empty()) {
		ret = to_utf8(_("unknown"));
	}

	return ret;
}

std::string tls_layer_impl::get_key_exchange() const
{
	std::string ret;

	char const* s = gnutls_kx_get_name(gnutls_kx_get(session_));
	if (s && *s) {
		ret = s;
	}

	if (ret.empty()) {
		ret = to_utf8(_("unknown"));
	}

	return ret;
}

std::string tls_layer_impl::get_cipher() const
{
	std::string ret;

	char const* cipher = gnutls_cipher_get_name(gnutls_cipher_get(session_));
	if (cipher && *cipher) {
		ret = cipher;
	}

	if (ret.empty()) {
		ret = to_utf8(_("unknown"));
	}

	return ret;
}

std::string tls_layer_impl::get_mac() const
{
	std::string ret;

	char const* mac = gnutls_mac_get_name(gnutls_mac_get(session_));
	if (mac && *mac) {
		ret = mac;
	}

	if (ret.empty()) {
		ret = to_utf8(_("unknown"));
	}

	return ret;
}

std::string tls_layer_impl::list_tls_ciphers(std::string const& priority)
{
	auto list = sprintf("Ciphers for %s:\n", priority.empty() ? ciphers : priority);

	gnutls_priority_t pcache;
	char const* err = nullptr;
	int ret = gnutls_priority_init(&pcache, priority.empty() ? ciphers : priority.c_str(), &err);
	if (ret < 0) {
		list += sprintf("gnutls_priority_init failed with code %d: %s", ret, err ? err : "Unknown error");
		return list;
	}
	else {
		for (unsigned int i = 0; ; ++i) {
			unsigned int idx;
			ret = gnutls_priority_get_cipher_suite_index(pcache, i, &idx);
			if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
				break;
			}
			if (ret == GNUTLS_E_UNKNOWN_CIPHER_SUITE) {
				continue;
			}

			gnutls_protocol_t version;
			unsigned char id[2];
			char const* name = gnutls_cipher_suite_info(idx, id, nullptr, nullptr, nullptr, &version);

			if (name != nullptr) {
				list += sprintf(
					"%-50s    0x%02x, 0x%02x    %s\n",
					name,
					(unsigned char)id[0],
					(unsigned char)id[1],
					gnutls_protocol_get_name(version));
			}
		}
	}

	return list;
}

int tls_layer_impl::do_call_gnutls_record_recv(void* data, size_t len)
{
	ssize_t res = gnutls_record_recv(session_, data, len);
	while ((res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) && can_read_from_socket_ && !gnutls_record_get_direction(session_)) {
		// Spurious EAGAIN. Can happen if GnuTLS gets a partial
		// record and the socket got closed.
		// The unexpected close is being ignored in this case, unless
		// gnutls_record_recv is being called again.
		// Manually call gnutls_record_recv as in case of eof on the socket,
		// we are not getting another receive event.
		logger_.log(logmsg::debug_verbose, L"gnutls_record_recv returned spurious EAGAIN");
		res = gnutls_record_recv(session_, data, len);
	}

	return static_cast<int>(res);
}

std::string tls_layer_impl::get_gnutls_version()
{
	char const* v = gnutls_check_version(nullptr);
	if (!v || !*v) {
		return "unknown";
	}

	return v;
}

void tls_layer_impl::set_hostname(native_string const& host)
{
	hostname_ = host;
	if (!hostname_.empty() && get_address_type(hostname_) == address_type::unknown) {
		auto const utf8 = to_utf8(hostname_);
		if (!utf8.empty()) {
			int res = gnutls_server_name_set(session_, GNUTLS_NAME_DNS, utf8.c_str(), utf8.size());
			if (res) {
				log_error(res, L"gnutls_server_name_set", logmsg::debug_warning);
			}
		}
	}
}

int tls_layer_impl::connect(native_string const& host, unsigned int port, address_type family)
{
	if (hostname_.empty()) {
		set_hostname(host);
	}

	return tls_layer_.next_layer_.connect(host, port, family);
}

std::vector<uint8_t> tls_layer_impl::get_session_parameters() const
{
	std::vector<uint8_t> ret;

	datum_holder d;
	int res = gnutls_session_get_data2(session_, &d);
	if (res) {
		logger_.log(logmsg::debug_warning, L"gnutls_session_get_data2 failed: %d", res);
	}
	else {
		ret.assign(d.data, d.data + d.size);
	}
	
	return ret;
}

std::vector<uint8_t> tls_layer_impl::get_raw_certificate() const
{
	std::vector<uint8_t> ret;

	// Implicitly trust certificate of primary socket
	unsigned int cert_list_size;
	gnutls_datum_t const* const cert_list = gnutls_certificate_get_peers(session_, &cert_list_size);
	if (cert_list && cert_list_size) {
		ret.assign(cert_list[0].data, cert_list[0].data + cert_list[0].size);
	}

	return ret;
}

}
