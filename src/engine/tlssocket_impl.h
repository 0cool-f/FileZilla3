#ifndef FILEZILLA_ENGINE_TLSSOCKET_IMPL_HEADER
#define FILEZILLA_ENGINE_TLSSOCKET_IMPL_HEADER

#if defined(_MSC_VER)
typedef std::make_signed_t<size_t> ssize_t;
#endif

#include <gnutls/gnutls.h>
#include "backend.h"
#include "socket.h"

#include <libfilezilla/buffer.hpp>

class CControlSocket;
class CTlsSocket;
class CTlsSocketImpl final
{
public:
	CTlsSocketImpl(CTlsSocket& tlsSocket, fz::socket& pSocket, CControlSocket* pOwner);
	~CTlsSocketImpl();

	int Handshake(const CTlsSocketImpl* pPrimarySocket = nullptr, bool try_resume = 0);

	int Read(void *buffer, unsigned int size, int& error);
	int Peek(void *buffer, unsigned int size, int& error);
	int Write(const void *buffer, unsigned int size, int& error);

	int Shutdown(bool silenceReadErrors);

	void TrustCurrentCert(bool trusted);

	CTlsSocket::TlsState GetState() const { return m_tlsState; }

	std::wstring GetProtocolName();
	std::wstring GetKeyExchange();
	std::wstring GetCipherName();
	std::wstring GetMacName();
	int GetAlgorithmWarnings();

	bool ResumedSession() const;

	static std::string ListTlsCiphers(std::string priority);

	bool SetClientCertificate(fz::native_string const& keyfile, fz::native_string const& certs, fz::native_string const& password);

	static std::wstring GetGnutlsVersion();

protected:
	bool Init();
	void Uninit();

	bool InitSession();
	void UninitSession();
	bool CopySessionData(CTlsSocketImpl const* pPrimarySocket);

	void OnRateAvailable(CRateLimiter::rate_direction direction);

	void ContinueWrite();
	int ContinueHandshake();
	void ContinueShutdown();

	int VerifyCertificate();
	bool CertificateIsBlacklisted(std::vector<CCertificate> const& certificates);

	void LogError(int code, std::wstring const& function, MessageType logLegel = MessageType::Error);
	void PrintAlert(MessageType logLevel);

	// Failure logs the error, uninits the session and sends a close event
	void Failure(int code, bool send_close, std::wstring const& function = std::wstring());

	static ssize_t PushFunction(gnutls_transport_ptr_t ptr, const void* data, size_t len);
	static ssize_t PullFunction(gnutls_transport_ptr_t ptr, void* data, size_t len);
	ssize_t PushFunction(const void* data, size_t len);
	ssize_t PullFunction(void* data, size_t len);

	int DoCallGnutlsRecordRecv(void* data, size_t len);

	void TriggerEvents();

	void operator()(fz::event_base const& ev);
	void OnSocketEvent(fz::socket_event_source* source, fz::socket_event_flag t, int error);

	void OnRead();
	void OnSend();

	bool GetSortedPeerCertificates(gnutls_x509_crt_t *& certs, unsigned int & certs_size);

	bool ExtractCert(gnutls_x509_crt_t const& cert, CCertificate& out);
	std::vector<CCertificate::SubjectName> GetCertSubjectAltNames(gnutls_x509_crt_t cert);

	void PrintVerificationError(int status);

	CTlsSocket& tlsSocket_;

	CTlsSocket::TlsState m_tlsState{ CTlsSocket::TlsState::noconn };

	CControlSocket* m_pOwner{};

	bool m_initialized{};
	gnutls_session_t m_session{};

	gnutls_certificate_credentials_t m_certCredentials{};

	bool m_canReadFromSocket{true};
	bool m_canWriteToSocket{true};

	fz::socket& m_socket;
	std::unique_ptr<CSocketBackend> socketBackend_;

	bool shutdown_requested_{};
	bool shutdown_silence_read_errors_{};

	// Due to the strange gnutls_record_send semantics, call it again
	// with 0 data and 0 length after GNUTLS_E_AGAIN and store the number
	// of bytes written. These bytes get skipped on next write from the
	// application.
	// This avoids the rule to call it again with the -same- data after
	// GNUTLS_E_AGAIN.
	bool m_lastReadFailed{false};
	bool m_lastWriteFailed{false};
	unsigned int m_writeSkip{};

	fz::buffer peekBuffer_;

	gnutls_datum_t m_implicitTrustedCert{};

	bool m_socket_eof{};
	int m_socket_error{ECONNABORTED}; // Set in the push and pull functions if reading/writing fails fatally

	friend class CTlsSocket;
	friend class CTlsSocketCallbacks;

	fz::native_string hostname_;
	unsigned int port_{};

};

#endif
