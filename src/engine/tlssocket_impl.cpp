#include <filezilla.h>
#include "engineprivate.h"
#include "socket_errors.h"
#include "tlssocket.h"
#include "tlssocket_impl.h"
#include "tls_system_trust_store_impl.h"
#include "ControlSocket.h"

#include <libfilezilla/iputils.hpp>

#include <gnutls/x509.h>

#include <algorithm>

#include <string.h>

static_assert(GNUTLS_VERSION_NUMBER != 0x030604, "Using TLS 1.3 with this version of GnuTLS does not work, update your version of GnuTLS");

#include <string_view>

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
CControlSocket* pLoggingControlSocket;
void log_func(int level, char const* msg)
{
	if (!msg || !pLoggingControlSocket) {
		return;
	}
	std::wstring s = fz::to_wstring(msg);
	fz::trim(s);
	pLoggingControlSocket->LogMessage(MessageType::Debug_Debug, L"tls: %d %s", level, s);
}
#endif

class CTlsSocketCallbacks
{
public:
	static int handshake_hook_func(gnutls_session_t session, unsigned int htype, unsigned int post, unsigned int incoming)
	{
		if (!session) {
			return 0;
		}
		auto* tls = reinterpret_cast<CTlsSocketImpl*>(gnutls_session_get_ptr(session));
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

		tls->m_pOwner->LogMessage(MessageType::Debug_Debug, L"TLS handshake: %s %s", prefix, name);

		return 0;
	}
};

namespace {
extern "C" int handshake_hook_func(gnutls_session_t session, unsigned int htype, unsigned int post, unsigned int incoming, gnutls_datum_t const*)
{
	return CTlsSocketCallbacks::handshake_hook_func(session, htype, post, incoming);
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

CTlsSocketImpl::CTlsSocketImpl(CTlsSocket& tlsSocket, CControlSocket* pOwner)
	: tlsSocket_(tlsSocket)
	, m_pOwner(pOwner)
{
}

CTlsSocketImpl::~CTlsSocketImpl()
{
	Uninit();
}

bool CTlsSocketImpl::Init()
{
	// This function initializes GnuTLS
	if (!m_initialized) {
		m_initialized = true;
		int res = gnutls_global_init();
		if (res) {
			LogError(res, L"gnutls_global_init");
			Uninit();
			return false;
		}

#if TLSDEBUG
		if (!pLoggingControlSocket) {
			pLoggingControlSocket = m_pOwner;
			gnutls_global_set_log_function(log_func);
			gnutls_global_set_log_level(99);
		}
#endif
	}

	if (!m_certCredentials) {
		int res = gnutls_certificate_allocate_credentials(&m_certCredentials);
		if (res < 0) {
			LogError(res, L"gnutls_certificate_allocate_credentials");
			Uninit();
			return false;
		}
	}

	if (!InitSession()) {
		return false;
	}

	// At this point, we can start shaking hands.
	return true;
}

bool CTlsSocketImpl::SetClientCertificate(fz::native_string const& keyfile, fz::native_string const& certs, fz::native_string const& password)
{
	if (!m_certCredentials) {
		return false;
	}

	int res = gnutls_certificate_set_x509_key_file2(m_certCredentials, fz::to_string(certs).c_str(),
		fz::to_string(keyfile).c_str(), GNUTLS_X509_FMT_PEM, password.empty() ? nullptr : fz::to_utf8(password).c_str(), 0);
	if (res < 0) {
		LogError(res, L"gnutls_certificate_set_x509_key_file2");
		Uninit();
		return false;
	}

	return true;
}

bool CTlsSocketImpl::InitSession()
{
	if (!m_certCredentials) {
		Uninit();
		return false;
	}

	int res = gnutls_init(&m_session, GNUTLS_CLIENT);
	if (res) {
		LogError(res, L"gnutls_init");
		Uninit();
		return false;
	}

	// For use in callbacks
	gnutls_session_set_ptr(m_session, this);

	// Even though the name gnutls_db_set_cache_expiration
	// implies expiration of some cache, it also governs
	// the actual session lifetime, independend whether the
	// session is cached or not.
	gnutls_db_set_cache_expiration(m_session, 100000000);

	res = gnutls_priority_set_direct(m_session, ciphers, nullptr);
	if (res) {
		LogError(res, L"gnutls_priority_set_direct");
		Uninit();
		return false;
	}

	gnutls_dh_set_prime_bits(m_session, 1024);

	gnutls_credentials_set(m_session, GNUTLS_CRD_CERTIFICATE, m_certCredentials);

	// Setup transport functions
	gnutls_transport_set_push_function(m_session, PushFunction);
	gnutls_transport_set_pull_function(m_session, PullFunction);
	gnutls_transport_set_ptr(m_session, (gnutls_transport_ptr_t)this);

	return true;
}

void CTlsSocketImpl::Uninit()
{
	UninitSession();

	if (m_certCredentials) {
		gnutls_certificate_free_credentials(m_certCredentials);
		m_certCredentials = nullptr;
	}

	if (m_initialized) {
		m_initialized = false;
		gnutls_global_deinit();
	}

	state_ = fz::socket_state::failed;

#if TLSDEBUG
	if (pLoggingControlSocket == m_pOwner) {
		pLoggingControlSocket = nullptr;
	}
#endif
}


void CTlsSocketImpl::UninitSession()
{
	if (m_session) {
		gnutls_deinit(m_session);
		m_session = nullptr;
	}
}


void CTlsSocketImpl::LogError(int code, std::wstring const& function, MessageType logLevel)
{
	if (logLevel < MessageType::Debug_Warning && state_ >= fz::socket_state::shut_down && shutdown_silence_read_errors_) {
		logLevel = MessageType::Debug_Warning;
	}

	if (code == GNUTLS_E_WARNING_ALERT_RECEIVED || code == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		PrintAlert(logLevel);
	}
	else if (code == GNUTLS_E_PULL_ERROR) {
		if (function.empty()) {
			m_pOwner->LogMessage(MessageType::Debug_Warning, L"GnuTLS could not read from socket: %s", fz::socket_error_description(m_socket_error));
		}
		else {
			m_pOwner->LogMessage(MessageType::Debug_Warning, L"GnuTLS could not read from socket in %s: %s", function, fz::socket_error_description(m_socket_error));
		}
	}
	else if (code == GNUTLS_E_PUSH_ERROR) {
		if (function.empty()) {
			m_pOwner->LogMessage(MessageType::Debug_Warning, L"GnuTLS could not write to socket: %s", fz::socket_error_description(m_socket_error));
		}
		else {
			m_pOwner->LogMessage(MessageType::Debug_Warning, L"GnuTLS could not write to socket in %s: %s", function, fz::socket_error_description(m_socket_error));
		}
	}
	else {
		char const* error = gnutls_strerror(code);
		if (error) {
			if (function.empty()) {
				m_pOwner->LogMessage(logLevel, _("GnuTLS error %d: %s"), code, error);
			}
			else {
				m_pOwner->LogMessage(logLevel, _("GnuTLS error %d in %s: %s"), code, function, error);
			}
		}
		else {
			if (function.empty()) {
				m_pOwner->LogMessage(logLevel, _("GnuTLS error %d"), code);
			}
			else {
				m_pOwner->LogMessage(logLevel, _("GnuTLS error %d in %s"), code, function);
			}
		}
	}
}

void CTlsSocketImpl::PrintAlert(MessageType logLevel)
{
	gnutls_alert_description_t last_alert = gnutls_alert_get(m_session);
	char const* alert = gnutls_alert_get_name(last_alert);
	if (alert) {
		m_pOwner->LogMessage(logLevel, _("Received TLS alert from the server: %s (%d)"), alert, last_alert);
	}
	else {
		m_pOwner->LogMessage(logLevel, _("Received unknown TLS alert %d from the server"), last_alert);
	}
}

ssize_t CTlsSocketImpl::PushFunction(gnutls_transport_ptr_t ptr, const void* data, size_t len)
{
	return ((CTlsSocketImpl*)ptr)->PushFunction(data, len);
}

ssize_t CTlsSocketImpl::PullFunction(gnutls_transport_ptr_t ptr, void* data, size_t len)
{
	return ((CTlsSocketImpl*)ptr)->PullFunction(data, len);
}

ssize_t CTlsSocketImpl::PushFunction(void const* data, size_t len)
{
#if TLSDEBUG
	m_pOwner->LogMessage(MessageType::Debug_Debug, L"CTlsSocketImpl::PushFunction(%d)", len);
#endif
	if (!m_canWriteToSocket) {
		gnutls_transport_set_errno(m_session, EAGAIN);
		return -1;
	}

	int error;
	int written = tlsSocket_.next_layer_.write(data, static_cast<unsigned int>(len), error);

	if (written < 0) {
		m_canWriteToSocket = false;
		if (error == EAGAIN) {
			m_socket_error = error;
		}
		gnutls_transport_set_errno(m_session, error);
#if TLSDEBUG
		m_pOwner->LogMessage(MessageType::Debug_Debug, L"  returning -1 due to %d", error);
#endif
		return -1;
	}

#if TLSDEBUG
	m_pOwner->LogMessage(MessageType::Debug_Debug, L"  returning %d", written);
#endif

	return written;
}

ssize_t CTlsSocketImpl::PullFunction(void* data, size_t len)
{
#if TLSDEBUG
	m_pOwner->LogMessage(MessageType::Debug_Debug, L"CTlsSocketImpl::PullFunction(%d)",  (int)len);
#endif

	if (!m_canReadFromSocket) {
		gnutls_transport_set_errno(m_session, EAGAIN);
		return -1;
	}

	int error;
	int read = tlsSocket_.next_layer_.read(data, static_cast<unsigned int>(len), error);
	if (read < 0) {
		m_canReadFromSocket = false;
		if (error != EAGAIN) {
			m_socket_error = error;
		}
		gnutls_transport_set_errno(m_session, error);
#if TLSDEBUG
		m_pOwner->LogMessage(MessageType::Debug_Debug, L"  returning -1 due to %d", error);
#endif
		return -1;
	}

	if (!read) {
		m_socket_eof = true;
	}

#if TLSDEBUG
	m_pOwner->LogMessage(MessageType::Debug_Debug, L"  returning %d", read);
#endif

	return read;
}

void CTlsSocketImpl::operator()(fz::event_base const& ev)
{
	fz::dispatch<fz::socket_event, fz::hostaddress_event>(ev, this
		, &CTlsSocketImpl::OnSocketEvent
		, &CTlsSocketImpl::forward_hostaddress_event);
}

void CTlsSocketImpl::forward_hostaddress_event(fz::socket_event_source* source, std::string const& address)
{
	tlsSocket_.forward_hostaddress_event(source, address);
}

void CTlsSocketImpl::OnSocketEvent(fz::socket_event_source* s, fz::socket_event_flag t, int error)
{
	if (!m_session) {
		return;
	}

	if (t == fz::socket_event_flag::connection_next) {
		tlsSocket_.forward_socket_event(s, t, error);
		return;
	}

	if (error) {
		m_socket_error = error;
		Uninit();
		tlsSocket_.forward_socket_event(s, t, error);
		return;
	}

	switch (t)
	{
	case fz::socket_event_flag::read:
		OnRead();
		break;
	case fz::socket_event_flag::write:
		OnSend();
		break;
	case fz::socket_event_flag::connection:
		if (hostname_.empty()) {
			set_hostname(tlsSocket_.next_layer_.peer_host());
		}
	default:
		break;
	}
}

void CTlsSocketImpl::OnRead()
{
	m_pOwner->LogMessage(MessageType::Debug_Debug, L"CTlsSocketImpl::OnRead()");

	m_canReadFromSocket = true;

	if (!m_session) {
		return;
	}

	if (state_ == fz::socket_state::connecting) {
		ContinueHandshake();
	}
	else if (state_ == fz::socket_state::connected || state_ == fz::socket_state::shutting_down || state_ == fz::socket_state::shut_down) {
		if (tlsSocket_.m_pEvtHandler) {
			tlsSocket_.m_pEvtHandler->send_event<fz::socket_event>(&tlsSocket_, fz::socket_event_flag::read, 0);
		}
	}
}

void CTlsSocketImpl::OnSend()
{
	m_pOwner->LogMessage(MessageType::Debug_Debug, L"CTlsSocketImpl::OnSend()");

	m_canWriteToSocket = true;

	if (!m_session) {
		return;
	}

	if (state_ == fz::socket_state::connecting) {
		ContinueHandshake();
	}
	else if (state_ == fz::socket_state::shutting_down) {
		int res = ContinueShutdown();
		if (res != EAGAIN) {
			if (tlsSocket_.m_pEvtHandler) {
				tlsSocket_.m_pEvtHandler->send_event<fz::socket_event>(&tlsSocket_, fz::socket_event_flag::write, res);
			}
		}
	}
	else if (state_ == fz::socket_state::connected) {
		ContinueWrite();
	}
}

void CTlsSocketImpl::ContinueWrite()
{
	if (m_lastWriteFailed) {
		ssize_t res = GNUTLS_E_AGAIN;
		while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && m_canWriteToSocket) {
			res = gnutls_record_send(m_session, nullptr, 0);
		}

		if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
			return;
		}

		if (res < 0) {
			Failure(static_cast<int>(res), true);
			return;
		}

		m_writeSkip += static_cast<int>(res);
		m_lastWriteFailed = false;
		if (tlsSocket_.m_pEvtHandler) {
			tlsSocket_.m_pEvtHandler->send_event<fz::socket_event>(&tlsSocket_, fz::socket_event_flag::write, 0);
		}
	}
}

bool CTlsSocketImpl::ResumedSession() const
{
	return gnutls_session_is_resumed(m_session) != 0;
}

bool CTlsSocketImpl::client_handshake(std::vector<uint8_t> const& session_to_resume, std::vector<uint8_t> const& required_certificate, fz::native_string const& session_hostname)
{
	m_pOwner->LogMessage(MessageType::Debug_Verbose, L"CTlsSocketImpl::client_handshake()");

	if (state_ != fz::socket_state::none) {
		m_pOwner->LogMessage(MessageType::Debug_Warning, L"Called CTlsSocketImpl::client_handshake on a socket that isn't idle");
		return false;
	}

	if (!Init()) {
		return false;
	}

	state_ = fz::socket_state::connecting;

	required_certificate_ = required_certificate;

	if (!session_to_resume.empty()) {
		int res = gnutls_session_set_data(m_session, session_to_resume.data(), session_to_resume.size());
		if (res) {
			m_pOwner->LogMessage(MessageType::Debug_Info, L"gnutls_session_set_data failed: %d. Going to reinitialize session.", res);
			UninitSession();
			if (!InitSession()) {
				return false;
			}
		}
		else {
			m_pOwner->LogMessage(MessageType::Debug_Info, L"Trying to resume existing TLS session.");
		}
	}

	if (m_pOwner->ShouldLog(MessageType::Debug_Debug)) {
		gnutls_handshake_set_hook_function(m_session, GNUTLS_HANDSHAKE_ANY, GNUTLS_HOOK_BOTH, &handshake_hook_func);
	}

	if (!session_hostname.empty()) {
		set_hostname(session_hostname);
	}

	if (tlsSocket_.next_layer_.get_state() != fz::socket_state::connected) {
		return true;
	}

	if (hostname_.empty()) {
		set_hostname(tlsSocket_.next_layer_.peer_host());
	}
	return ContinueHandshake() == EAGAIN;
}

int CTlsSocketImpl::ContinueHandshake()
{
	m_pOwner->LogMessage(MessageType::Debug_Verbose, L"CTlsSocketImpl::ContinueHandshake()");
	assert(m_session);
	assert(state_ == fz::socket_state::connecting);

	int res = gnutls_handshake(m_session);
	while (res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) {
		if (!(gnutls_record_get_direction(m_session) ? m_canWriteToSocket : m_canReadFromSocket)) {
			break;
		}
		res = gnutls_handshake(m_session);
	}
	if (!res) {
		m_pOwner->LogMessage(MessageType::Debug_Info, L"TLS Handshake successful");
		handshake_successful_ = true;

		if (ResumedSession()) {
			m_pOwner->LogMessage(MessageType::Debug_Info, L"TLS Session resumed");
		}

		std::wstring const protocol = GetProtocolName();
		std::wstring const keyExchange = GetKeyExchange();
		std::wstring const cipherName = GetCipherName();
		std::wstring const macName = GetMacName();

		m_pOwner->LogMessage(MessageType::Debug_Info, L"Protocol: %s, Key exchange: %s, Cipher: %s, MAC: %s", protocol, keyExchange, cipherName, macName);

		return VerifyCertificate();
	}
	else if (res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) {
		return EAGAIN;
	}

	Failure(res, true);

	return m_socket_error ? m_socket_error : ECONNABORTED;
}

int CTlsSocketImpl::read(void *buffer, unsigned int len, int& error)
{
	if (state_ == fz::socket_state::connecting) {
		error = EAGAIN;
		return -1;
	}
	else if (state_ != fz::socket_state::connected && state_ != fz::socket_state::shutting_down && state_ != fz::socket_state::shut_down) {
		error = ENOTCONN;
		return -1;
	}

	int res = DoCallGnutlsRecordRecv(buffer, len);
	if (res >= 0) {
		if (!res) {
			// Peer did already initiate a shutdown, reply to it
			gnutls_bye(m_session, GNUTLS_SHUT_WR);
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
		Failure(res, false, L"gnutls_record_recv");
		error = m_socket_error;
	}

	return -1;
}

int CTlsSocketImpl::write(void const* buffer, unsigned int len, int& error)
{
	if (state_ == fz::socket_state::connecting) {
		error = EAGAIN;
		return -1;
	}
	else if (state_ == fz::socket_state::shutting_down || state_ == fz::socket_state::shut_down) {
		error = ESHUTDOWN;
		return -1;
	}
	else if (state_ != fz::socket_state::connected) {
		error = ENOTCONN;
		return -1;
	}

	if (m_lastWriteFailed) {
		error = EAGAIN;
		return -1;
	}

	if (m_writeSkip >= len) {
		m_writeSkip -= len;
		return len;
	}

	len -= m_writeSkip;
	buffer = (char*)buffer + m_writeSkip;

	ssize_t res = gnutls_record_send(m_session, buffer, len);

	while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && m_canWriteToSocket) {
		res = gnutls_record_send(m_session, nullptr, 0);
	}

	if (res >= 0) {
		error = 0;
		int written = static_cast<int>(res) + m_writeSkip;
		m_writeSkip = 0;
		return written;
	}

	if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
		if (m_writeSkip) {
			error = 0;
			int written = m_writeSkip;
			m_writeSkip = 0;
			return written;
		}
		else {
			error = EAGAIN;
			m_lastWriteFailed = true;
			return -1;
		}
	}
	else {
		Failure(static_cast<int>(res), false, L"gnutls_record_send");
		error = m_socket_error;
		return -1;
	}
}

void CTlsSocketImpl::Failure(int code, bool send_close, std::wstring const& function)
{
	m_pOwner->LogMessage(MessageType::Debug_Debug, L"CTlsSocketImpl::Failure(%d)", code);
	if (code) {
		LogError(code, function);
		if (m_socket_eof) {
			if (code == GNUTLS_E_UNEXPECTED_PACKET_LENGTH
#ifdef GNUTLS_E_PREMATURE_TERMINATION
				|| code == GNUTLS_E_PREMATURE_TERMINATION
#endif
				)
			{
				if (state_ != fz::socket_state::shut_down || !shutdown_silence_read_errors_) {
					m_pOwner->LogMessage(MessageType::Status, _("Server did not properly shut down TLS connection"));
				}
			}
		}
	}

	auto const oldState = state_;

	Uninit();

	if (send_close && tlsSocket_.m_pEvtHandler) {
		int error = m_socket_error;
		if (!error) {
			error = ECONNABORTED;
		}
		if (oldState == fz::socket_state::connecting) {
			tlsSocket_.m_pEvtHandler->send_event<fz::socket_event>(&tlsSocket_, fz::socket_event_flag::connection, error);
		}
		else {
			tlsSocket_.m_pEvtHandler->send_event<fz::socket_event>(&tlsSocket_, fz::socket_event_flag::read, error);
		}
	}
}

int CTlsSocketImpl::shutdown()
{
	m_pOwner->LogMessage(MessageType::Debug_Verbose, L"CTlsSocketImpl::Shutdown()");

	if (state_ == fz::socket_state::shut_down) {
		return 0;
	}
	else if (state_ == fz::socket_state::shutting_down) {
		return EAGAIN;
	}
	else if (state_ != fz::socket_state::connected) {
		return ENOTCONN;
	}

	state_ = fz::socket_state::shutting_down;

	return ContinueShutdown();
}

int CTlsSocketImpl::ContinueShutdown()
{
	m_pOwner->LogMessage(MessageType::Debug_Verbose, L"CTlsSocketImpl::ContinueShutdown()");

	if (!sent_closure_alert_) {
		int res = gnutls_bye(m_session, GNUTLS_SHUT_WR);
		while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && m_canWriteToSocket) {
			res = gnutls_bye(m_session, GNUTLS_SHUT_WR);
		}
		if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
			return EAGAIN;
		}
		else if (res) {
			Failure(res, false, L"gnutls_bye");
			return m_socket_error ? m_socket_error : ECONNABORTED;
		}
		sent_closure_alert_ = true;
	}
	
	int res = tlsSocket_.next_layer_.shutdown();
	if (res == EAGAIN) {
		return EAGAIN;
	}

	if (!res) {
		state_ = fz::socket_state::shut_down;
	}
	else {
		m_socket_error = res;
		Failure(0, false);
	}
	return res;
}

void CTlsSocketImpl::TrustCurrentCert(bool trusted)
{
	if (state_ != fz::socket_state::connecting && !handshake_successful_) {
		m_pOwner->LogMessage(MessageType::Debug_Warning, L"TrustCurrentCert called at wrong time.");
		return;
	}

	if (trusted) {
		state_ = fz::socket_state::connected;

		if (tlsSocket_.m_pEvtHandler) {
			tlsSocket_.m_pEvtHandler->send_event<fz::socket_event>(&tlsSocket_, fz::socket_event_flag::connection, 0);
			if (m_canReadFromSocket) {
				tlsSocket_.m_pEvtHandler->send_event<fz::socket_event>(&tlsSocket_, fz::socket_event_flag::read, 0);
			}
			if (m_canWriteToSocket) {
				tlsSocket_.m_pEvtHandler->send_event<fz::socket_event>(&tlsSocket_, fz::socket_event_flag::write, 0);
			}
		}

		return;
	}

	m_pOwner->LogMessage(MessageType::Error, _("Remote certificate not trusted."));
	Failure(0, true);
}

static std::wstring bin2hex(unsigned char const* in, size_t size)
{
	std::wstring str;
	str.reserve(size * 3);
	for (size_t i = 0; i < size; ++i) {
		if (i) {
			str += ':';
		}
		str += fz::int_to_hex_char<wchar_t>(in[i] >> 4);
		str += fz::int_to_hex_char<wchar_t>(in[i] & 0xf);
	}

	return str;
}


bool CTlsSocketImpl::ExtractCert(gnutls_x509_crt_t const& cert, CCertificate& out)
{
	fz::datetime expirationTime(gnutls_x509_crt_get_expiration_time(cert), fz::datetime::seconds);
	fz::datetime activationTime(gnutls_x509_crt_get_activation_time(cert), fz::datetime::seconds);

	// Get the serial number of the certificate
	unsigned char buffer[40];
	size_t size = sizeof(buffer);
	int res = gnutls_x509_crt_get_serial(cert, buffer, &size);
	if (res != 0) {
		size = 0;
	}

	std::wstring serial = bin2hex(buffer, size);

	unsigned int pkBits;
	int pkAlgo = gnutls_x509_crt_get_pk_algorithm(cert, &pkBits);
	std::wstring pkAlgoName;
	if (pkAlgo >= 0) {
		char const* pAlgo = gnutls_pk_algorithm_get_name((gnutls_pk_algorithm_t)pkAlgo);
		if (pAlgo) {
			pkAlgoName = fz::to_wstring_from_utf8(pAlgo);
		}
	}

	int signAlgo = gnutls_x509_crt_get_signature_algorithm(cert);
	std::wstring signAlgoName;
	if (signAlgo >= 0) {
		char const* pAlgo = gnutls_sign_algorithm_get_name((gnutls_sign_algorithm_t)signAlgo);
		if (pAlgo) {
			signAlgoName = fz::to_wstring_from_utf8(pAlgo);
		}
	}

	std::wstring subject, issuer;

	datum_holder raw_subject;
	if (!gnutls_x509_crt_get_dn3(cert, &raw_subject, 0)) {
		subject = fz::to_wstring_from_utf8(raw_subject.to_string());
	}
	else {
		LogError(res, L"gnutls_x509_crt_get_dn3");
	}
	if (subject.empty()) {
		m_pOwner->LogMessage(MessageType::Error, _("Could not get distinguished name of certificate subject, gnutls_x509_get_dn failed"));
		return false;
	}

	std::vector<CCertificate::SubjectName> alt_subject_names = GetCertSubjectAltNames(cert);

	datum_holder raw_issuer;
	if (!gnutls_x509_crt_get_issuer_dn3(cert, &raw_issuer, 0)) {
		issuer = fz::to_wstring_from_utf8(raw_issuer.to_string());
	}
	else {
		LogError(res, L"gnutls_x509_crt_get_issuer_dn3");
	}
	if (issuer.empty() ) {
		m_pOwner->LogMessage(MessageType::Error, _("Could not get distinguished name of certificate issuer, gnutls_x509_get_issuer_dn failed"));
		return false;
	}

	std::wstring fingerprint_sha256;
	std::wstring fingerprint_sha1;

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
		m_pOwner->LogMessage(MessageType::Error, L"gnutls_x509_crt_get_issuer_dn");
		return false;
	}
	std::vector<uint8_t> data(der.data, der.data + der.size);

	out = CCertificate(
		std::move(data),
		activationTime, expirationTime,
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


std::vector<CCertificate::SubjectName> CTlsSocketImpl::GetCertSubjectAltNames(gnutls_x509_crt_t cert)
{
	std::vector<CCertificate::SubjectName> ret;

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
			std::wstring dns = fz::to_wstring_from_utf8(san);
			if (!dns.empty()) {
				ret.emplace_back(CCertificate::SubjectName{std::move(dns), type_or_error == GNUTLS_SAN_DNSNAME});
			}
		}
		else if (type_or_error == GNUTLS_SAN_IPADDRESS) {
			std::wstring ip = fz::to_wstring(fz::socket::address_to_string(san, static_cast<int>(san_size)));
			if (!ip.empty()) {
				ret.emplace_back(CCertificate::SubjectName{std::move(ip), false});
			}
		}
	}
	return ret;
}

bool CTlsSocketImpl::CertificateIsBlacklisted(std::vector<CCertificate> const&)
{
	return false;
}


int CTlsSocketImpl::GetAlgorithmWarnings()
{
	int algorithmWarnings{};

	switch (gnutls_protocol_get_version(m_session))
	{
		case GNUTLS_SSL3:
		case GNUTLS_VERSION_UNKNOWN:
			algorithmWarnings |= CCertificateNotification::tlsver;
			break;
		default:
			break;
	}

	switch (gnutls_cipher_get(m_session)) {
		case GNUTLS_CIPHER_UNKNOWN:
		case GNUTLS_CIPHER_NULL:
		case GNUTLS_CIPHER_ARCFOUR_128:
		case GNUTLS_CIPHER_3DES_CBC:
		case GNUTLS_CIPHER_ARCFOUR_40:
		case GNUTLS_CIPHER_RC2_40_CBC:
		case GNUTLS_CIPHER_DES_CBC:
			algorithmWarnings |= CCertificateNotification::cipher;
			break;
		default:
			break;
	}

	switch (gnutls_mac_get(m_session)) {
		case GNUTLS_MAC_UNKNOWN:
		case GNUTLS_MAC_NULL:
		case GNUTLS_MAC_MD5:
		case GNUTLS_MAC_MD2:
		case GNUTLS_MAC_UMAC_96:
			algorithmWarnings |= CCertificateNotification::mac;
			break;
		default:
			break;
	}

	switch (gnutls_kx_get(m_session)) {
		case GNUTLS_KX_UNKNOWN:
		case GNUTLS_KX_ANON_DH:
		case GNUTLS_KX_RSA_EXPORT:
		case GNUTLS_KX_ANON_ECDH:
			algorithmWarnings |= CCertificateNotification::kex;
		default:
			break;
	}

	return algorithmWarnings;
}


bool CTlsSocketImpl::GetSortedPeerCertificates(gnutls_x509_crt_t *& certs, unsigned int & certs_size)
{
	certs = nullptr;
	certs_size = 0;

	// First get unsorted list of peer certificates in DER
	unsigned int cert_list_size;
	const gnutls_datum_t* cert_list = gnutls_certificate_get_peers(m_session, &cert_list_size);
	if (!cert_list || !cert_list_size) {
		m_pOwner->LogMessage(MessageType::Error, _("gnutls_certificate_get_peers returned no certificates"));
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
			m_pOwner->LogMessage(MessageType::Error, _("gnutls_pem_base64_encode2 failed"));
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
		m_pOwner->LogMessage(MessageType::Error, _("Server sent unsorted certificate chain in violation of the TLS specifications"));
		res = gnutls_x509_crt_list_import2(&certs, &certs_size, &concated_certs, GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_SORT);
	}

	delete[] concated_certs.data;

	if (res != GNUTLS_E_SUCCESS) {
		certs = nullptr;
		certs_size = 0;
		m_pOwner->LogMessage(MessageType::Error, _("Could not sort peer certificates"));
		return false;
	}

	return true;
}

void CTlsSocketImpl::PrintVerificationError(int status)
{
	gnutls_datum_t buffer{};
	gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509, &buffer, 0);
	if (buffer.data) {
		m_pOwner->LogMessage(MessageType::Debug_Warning, L"Gnutls Verification status: %s", buffer.data);
		gnutls_free(buffer.data);
	}

	if (status & GNUTLS_CERT_REVOKED) {
		m_pOwner->LogMessage(MessageType::Error, _("Beware! Certificate has been revoked"));

		// The remaining errors are no longer of interest
		return;
	}
	if (status & GNUTLS_CERT_SIGNATURE_FAILURE) {
		m_pOwner->LogMessage(MessageType::Error, _("Certificate signature verification failed"));
		status &= ~GNUTLS_CERT_SIGNATURE_FAILURE;
	}
	if (status & GNUTLS_CERT_INSECURE_ALGORITHM) {
		m_pOwner->LogMessage(MessageType::Error, _("A certificate in the chain was signed using an insecure algorithm"));
		status &= ~GNUTLS_CERT_INSECURE_ALGORITHM;
	}
	if (status & GNUTLS_CERT_SIGNER_NOT_CA) {
		m_pOwner->LogMessage(MessageType::Error, _("An issuer in the certificate chain is not a certificate authority"));
		status &= ~GNUTLS_CERT_SIGNER_NOT_CA;
	}
	if (status & GNUTLS_CERT_UNEXPECTED_OWNER) {
		m_pOwner->LogMessage(MessageType::Error, _("The server's hostname does not match the certificate's hostname"));
		status &= ~GNUTLS_CERT_UNEXPECTED_OWNER;
	}
#ifdef GNUTLS_CERT_MISSING_OCSP_STATUS
	if (status & GNUTLS_CERT_MISSING_OCSP_STATUS) {
		m_pOwner->LogMessage(MessageType::Error, _("The certificate requires the server to include an OCSP status in its response, but the OCSP status is missing."));
		status &= ~GNUTLS_CERT_MISSING_OCSP_STATUS;
	}
#endif
	if (status) {
		m_pOwner->LogMessage(MessageType::Error, _("Received certificate chain could not be verified. Verification status is %d."), status);
	}

}

int CTlsSocketImpl::VerifyCertificate()
{
	if (state_ != fz::socket_state::connecting) {
		m_pOwner->LogMessage(MessageType::Debug_Warning, L"VerifyCertificate called at wrong time");
		return ENOTCONN;
	}

	if (gnutls_certificate_type_get(m_session) != GNUTLS_CRT_X509) {
		m_pOwner->LogMessage(MessageType::Error, _("Unsupported certificate type"));
		Failure(0, true);
		return EOPNOTSUPP;
	}

	cert_list_holder certs;
	if (!GetSortedPeerCertificates(certs.certs, certs.certs_size)) {
		Failure(0, true);
		return EINVAL;
	}

	bool const uses_hostname = !hostname_.empty() && fz::get_address_type(hostname_) == fz::address_type::unknown;

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
	if (uses_hostname) {

		auto lease = m_pOwner->GetEngine().GetContext().GetTlsSystemTrustStore().impl_->lease();
		auto cred = std::get<0>(lease);
		if (cred) {
			gnutls_credentials_set(m_session, GNUTLS_CRD_CERTIFICATE, cred);
			unsigned int status = 0;
			int verifyResult = gnutls_certificate_verify_peers3(m_session, fz::to_utf8(hostname_).c_str(), &status);
			gnutls_credentials_set(m_session, GNUTLS_CRD_CERTIFICATE, m_certCredentials);
			std::get<1>(lease).unlock();

			if (verifyResult < 0) {
				m_pOwner->LogMessage(MessageType::Debug_Warning, L"gnutls_certificate_verify_peers2 returned %d with status %u", verifyResult, status);
				m_pOwner->LogMessage(MessageType::Error, _("Failed to verify peer certificate"));
				Failure(0, true);
				return EINVAL;
			}

			if (!status) {
				systemTrust = true;
			}
		}
		else {
			std::get<1>(lease).unlock();
			m_pOwner->LogMessage(MessageType::Debug_Warning, L"System trust store could not be loaded");
		}
	}

	if (!systemTrust) {
		// System trust store cannot verify this certificate. Allow three impairments:
		//
		// 1. For now, add the highest certificate from the chain to trust list. Otherwise
		// gnutls_certificate_verify_peers2 always stops with GNUTLS_CERT_SIGNER_NOT_FOUND
		// at the highest certificate in the chain.
		gnutls_x509_crt_t root{};
		clone_cert(certs.certs[certs.certs_size - 1], root);
		if (!root) {
			m_pOwner->LogMessage(MessageType::Error, _("Could not copy certificate"));
			Failure(0, true);
			return ECONNABORTED;
		}

		gnutls_x509_trust_list_t tlist;
		gnutls_certificate_get_trust_list(m_certCredentials, &tlist);
		if (gnutls_x509_trust_list_add_cas(tlist, &root, 1, 0) != 1) {
			m_pOwner->LogMessage(MessageType::Error, _("Could not add certificate to temporary trust list"));
			Failure(0, true);
			return ECONNABORTED;
		}

		// 2. Also disable time checks. We allow expired/not yet valid certificates, though only
		// after explicit user confirmation.
		gnutls_certificate_set_verify_flags(m_certCredentials, gnutls_certificate_get_verify_flags(m_certCredentials) | GNUTLS_VERIFY_DISABLE_TIME_CHECKS | GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS);

		unsigned int status = 0;
		int verifyResult = gnutls_certificate_verify_peers2(m_session, &status);

		if (verifyResult < 0) {
			m_pOwner->LogMessage(MessageType::Debug_Warning, L"gnutls_certificate_verify_peers2 returned %d with status %u", verifyResult, status);
			m_pOwner->LogMessage(MessageType::Error, _("Failed to verify peer certificate"));
			Failure(0, true);
			return EINVAL;
		}

		if (status != 0) {
			PrintVerificationError(status);

			Failure(0, true);
			return EINVAL;
		}

		// 3. Hostname mismatch
		if (uses_hostname) {
			if (!gnutls_x509_crt_check_hostname(certs.certs[0], fz::to_utf8(hostname_).c_str())) {
				hostnameMismatch = true;
				m_pOwner->LogMessage(MessageType::Debug_Warning, L"Hostname does not match certificate SANs");
			}
		}
	}

	datum_holder cert_der{};
	if (gnutls_x509_crt_export2(certs.certs[0], GNUTLS_X509_FMT_DER, &cert_der) != GNUTLS_E_SUCCESS) {
		Failure(0, true);
		return ECONNABORTED;
	}

	if (!required_certificate_.empty()) {
		auto v = std::string_view((char const*)cert_der.data, cert_der.size);
		auto first = fz::hex_encode<std::string>(required_certificate_);
		auto second = fz::hex_encode<std::string>(v);
		if (required_certificate_.size() != cert_der.size ||
			memcmp(required_certificate_.data(), cert_der.data, cert_der.size))
		{
			m_pOwner->LogMessage(MessageType::Error, _("Certificate of connection does not match expected certificate."));
			Failure(0, true);
			return EINVAL;
		}

		TrustCurrentCert(true);

		if (state_ != fz::socket_state::connected && state_ != fz::socket_state::shutting_down && state_ != fz::socket_state::shut_down) {
			return ECONNABORTED;
		}
		return 0;
	}

	m_pOwner->LogMessage(MessageType::Status, _("Verifying certificate..."));

	std::vector<CCertificate> certificates;
	certificates.reserve(certs.certs_size);
	for (unsigned int i = 0; i < certs.certs_size; ++i) {
		CCertificate cert;
		if (ExtractCert(certs.certs[i], cert)) {
			certificates.push_back(cert);
		}
		else {
			Failure(0, true);
			return ECONNABORTED;
		}
	}

	if (CertificateIsBlacklisted(certificates)) {
		Failure(0, true);
		return EINVAL;
	}

	int const algorithmWarnings = GetAlgorithmWarnings();

	int error;
	auto port = tlsSocket_.peer_port(error);
	if (port == -1) {
		m_socket_error = error;
		Failure(0, true);
		return ECONNABORTED;
	}

	CCertificateNotification *pNotification = new CCertificateNotification(
		fz::to_wstring(hostname_),
		port,
		GetProtocolName(),
		GetKeyExchange(),
		GetCipherName(),
		GetMacName(),
		algorithmWarnings,
		std::move(certificates),
		systemTrust,
		hostnameMismatch);

	// Finally, ask user to verify the certificate chain
	m_pOwner->SendAsyncRequest(pNotification);

	return EAGAIN;
}

std::wstring CTlsSocketImpl::GetProtocolName()
{
	std::wstring ret;

	char const* s = gnutls_protocol_get_name( gnutls_protocol_get_version( m_session ) );
	if (s && *s) {
		ret = fz::to_wstring_from_utf8(s);
	}

	if (ret.empty()) {
		ret = _("unknown");
	}

	return ret;
}

std::wstring CTlsSocketImpl::GetKeyExchange()
{
	std::wstring ret;

	char const* s = gnutls_kx_get_name( gnutls_kx_get( m_session ) );
	if (s && *s) {
		ret = fz::to_wstring_from_utf8(s);
	}

	if (ret.empty()) {
		ret = _("unknown");
	}

	return ret;
}

std::wstring CTlsSocketImpl::GetCipherName()
{
	std::wstring ret;

	char const* cipher = gnutls_cipher_get_name(gnutls_cipher_get(m_session));
	if (cipher && *cipher) {
		ret = fz::to_wstring_from_utf8(cipher);
	}

	if (ret.empty()) {
		ret = _("unknown");
	}

	return ret;
}

std::wstring CTlsSocketImpl::GetMacName()
{
	std::wstring ret;

	char const* mac = gnutls_mac_get_name(gnutls_mac_get(m_session));
	if (mac && *mac) {
		ret = fz::to_wstring_from_utf8(mac);
	}

	if (ret.empty()) {
		ret = _("unknown");
	}

	return ret;
}

std::string CTlsSocketImpl::ListTlsCiphers(std::string priority)
{
	if (priority.empty()) {
		priority = ciphers;
	}

	auto list = fz::sprintf("Ciphers for %s:\n", priority);

	gnutls_priority_t pcache;
	char const* err = nullptr;
	int ret = gnutls_priority_init(&pcache, priority.c_str(), &err);
	if (ret < 0) {
		list += fz::sprintf("gnutls_priority_init failed with code %d: %s", ret, err ? err : "Unknown error");
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
				list += fz::sprintf(
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

int CTlsSocketImpl::DoCallGnutlsRecordRecv(void* data, size_t len)
{
	ssize_t res = gnutls_record_recv(m_session, data, len);
	while ((res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) && m_canReadFromSocket && !gnutls_record_get_direction(m_session)) {
		// Spurious EAGAIN. Can happen if GnuTLS gets a partial
		// record and the socket got closed.
		// The unexpected close is being ignored in this case, unless
		// gnutls_record_recv is being called again.
		// Manually call gnutls_record_recv as in case of eof on the socket,
		// we are not getting another receive event.
		m_pOwner->LogMessage(MessageType::Debug_Verbose, L"gnutls_record_recv returned spurious EAGAIN");
		res = gnutls_record_recv(m_session, data, len);
	}

	return static_cast<int>(res);
}

std::wstring CTlsSocketImpl::GetGnutlsVersion()
{
	char const* v = gnutls_check_version(nullptr);
	if (!v || !*v) {
		return L"unknown";
	}

	return fz::to_wstring(v);
}

void CTlsSocketImpl::set_hostname(fz::native_string const& host)
{
	hostname_ = host;
	if (!hostname_.empty() && fz::get_address_type(hostname_) == fz::address_type::unknown) {
		auto const utf8 = fz::to_utf8(hostname_);
		if (!utf8.empty()) {
			int res = gnutls_server_name_set(m_session, GNUTLS_NAME_DNS, utf8.c_str(), utf8.size());
			if (res) {
				LogError(res, L"gnutls_server_name_set", MessageType::Debug_Warning);
			}
		}
	}
}

int CTlsSocketImpl::connect(fz::native_string const& host, unsigned int port, fz::address_type family)
{
	if (hostname_.empty()) {
		set_hostname(host);
	}

	return tlsSocket_.next_layer_.connect(host, port, family);
}

std::vector<uint8_t> CTlsSocketImpl::get_session_parameters() const
{
	std::vector<uint8_t> ret;

	datum_holder d;
	int res = gnutls_session_get_data2(m_session, &d);
	if (res) {
		m_pOwner->LogMessage(MessageType::Debug_Warning, L"gnutls_session_get_data2 failed: %d", res);
	}
	else {
		ret.assign(d.data, d.data + d.size);
	}
	
	return ret;
}

std::vector<uint8_t> CTlsSocketImpl::get_raw_certificate() const
{
	std::vector<uint8_t> ret;

	// Implicitly trust certificate of primary socket
	unsigned int cert_list_size;
	gnutls_datum_t const* const cert_list = gnutls_certificate_get_peers(m_session, &cert_list_size);
	if (cert_list && cert_list_size) {
		ret.assign(cert_list[0].data, cert_list[0].data + cert_list[0].size);
	}

	return ret;
}
