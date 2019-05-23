#ifndef FILEZILLA_ENGINE_TLSSOCKET_IMPL_HEADER
#define FILEZILLA_ENGINE_TLSSOCKET_IMPL_HEADER

#if defined(_MSC_VER)
typedef std::make_signed_t<size_t> ssize_t;
#endif

#include <gnutls/gnutls.h>
#include "backend.h"

#include <libfilezilla/buffer.hpp>
#include <libfilezilla/socket.hpp>

class CControlSocket;
class CTlsSocket;
class CTlsSocketImpl final
{
public:
	CTlsSocketImpl(CTlsSocket& tlsSocket, CControlSocket* pOwner);
	~CTlsSocketImpl();

	bool client_handshake(std::vector<uint8_t> const& session_to_resume, std::vector<uint8_t> const& required_certificate, fz::native_string const& session_hostname);

	int connect(fz::native_string const& host, unsigned int port, fz::address_type family);

	int read(void *buffer, unsigned int size, int& error);
	int write(void const* buffer, unsigned int size, int& error);

	int shutdown();

	void TrustCurrentCert(bool trusted);

	fz::socket_state get_state() const {
		return state_;
	}

	std::vector<uint8_t> get_session_parameters() const;
	std::vector<uint8_t> get_raw_certificate() const;

	std::wstring GetProtocolName();
	std::wstring GetKeyExchange();
	std::wstring GetCipherName();
	std::wstring GetMacName();
	int GetAlgorithmWarnings();

	bool ResumedSession() const;

	static std::string ListTlsCiphers(std::string priority);

	bool SetClientCertificate(fz::native_string const& keyfile, fz::native_string const& certs, fz::native_string const& password);

	static std::wstring GetGnutlsVersion();

private:
	bool Init();
	void Uninit();

	bool InitSession();
	void UninitSession();
	
	void ContinueWrite();
	int ContinueHandshake();
	int ContinueShutdown();

	int VerifyCertificate();
	bool CertificateIsBlacklisted(std::vector<CCertificate> const& certificates);

	void LogError(int code, std::wstring const& function, MessageType logLegel = MessageType::Error);
	void PrintAlert(MessageType logLevel);

	// Failure logs the error, uninits the session and sends a close event
	void Failure(int code, bool send_close, std::wstring const& function = std::wstring());

	static ssize_t PushFunction(gnutls_transport_ptr_t ptr, const void* data, size_t len);
	static ssize_t PullFunction(gnutls_transport_ptr_t ptr, void* data, size_t len);
	ssize_t PushFunction(void const* data, size_t len);
	ssize_t PullFunction(void* data, size_t len);

	int DoCallGnutlsRecordRecv(void* data, size_t len);

	void operator()(fz::event_base const& ev);
	void OnSocketEvent(fz::socket_event_source* source, fz::socket_event_flag t, int error);
	void forward_hostaddress_event(fz::socket_event_source* source, std::string const& address);

	void OnRead();
	void OnSend();

	bool GetSortedPeerCertificates(gnutls_x509_crt_t *& certs, unsigned int & certs_size);

	bool ExtractCert(gnutls_x509_crt_t const& cert, CCertificate& out);
	std::vector<CCertificate::SubjectName> GetCertSubjectAltNames(gnutls_x509_crt_t cert);

	void PrintVerificationError(int status);

	void set_hostname(fz::native_string const& host);

	CTlsSocket& tlsSocket_;

	fz::socket_state state_{};

	CControlSocket* m_pOwner{};

	bool m_initialized{};
	gnutls_session_t m_session{};

	gnutls_certificate_credentials_t m_certCredentials{};
	bool handshake_successful_{};
	bool sent_closure_alert_{};

	bool m_canReadFromSocket{false};
	bool m_canWriteToSocket{false};

	bool shutdown_silence_read_errors_{true};

	// Due to the strange gnutls_record_send semantics, call it again
	// with 0 data and 0 length after GNUTLS_E_AGAIN and store the number
	// of bytes written. These bytes get skipped on next write from the
	// application.
	// This avoids the rule to call it again with the -same- data after
	// GNUTLS_E_AGAIN.
	bool m_lastWriteFailed{false};
	unsigned int m_writeSkip{};

	std::vector<uint8_t> required_certificate_;

	bool m_socket_eof{};
	int m_socket_error{ECONNABORTED}; // Set in the push and pull functions if reading/writing fails fatally

	friend class CTlsSocket;
	friend class CTlsSocketCallbacks;

	fz::native_string hostname_;
};

#endif
