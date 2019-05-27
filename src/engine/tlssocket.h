#ifndef FILEZILLA_ENGINE_TLSSOCKET_HEADER
#define FILEZILLA_ENGINE_TLSSOCKET_HEADER

#include "backend.h"

class CControlSocket;
class CTlsSocketImpl;

namespace fz {
class tls_system_trust_store;
}

class CTlsSocket final : protected fz::event_handler, public SocketLayer
{
public:
	CTlsSocket(fz::event_handler* pEvtHandler, fz::socket_interface& layer, fz::tls_system_trust_store * systemTrustStore, CControlSocket* pOwner);
	virtual ~CTlsSocket();

	/**
	 * \brief Starts shaking hand for a new TLS session as client.
	 *
	 * Returns true if the handshake has started, false on error.
	 *
	 * If the handshake is started, wait for a connection event for the result.
	 *
	 * If a required certificate is passed, either in DER or PEM, the session's certificate
	 * must match the passed certificate or the handshake will fail.
	 */
	bool client_handshake(std::vector<uint8_t> const& session_to_resume = std::vector<uint8_t>(), std::vector<uint8_t> const& required_certificate = std::vector<uint8_t>(), fz::native_string const& session_hostname = fz::native_string());

	/// Gets session parameters for resumption
	std::vector<uint8_t> get_session_parameters() const;

	/// Gets the session's certificate in DER
	std::vector<uint8_t> get_raw_certificate() const;

	virtual int connect(fz::native_string const& host, unsigned int port, fz::address_type family = fz::address_type::unknown) override;

	virtual int read(void *buffer, unsigned int size, int& error) override;
	virtual int write(void const* buffer, unsigned int size, int& error) override;

	virtual int shutdown() override;

	void TrustCurrentCert(bool trusted);

	virtual fz::socket_state get_state() const override;

	std::wstring GetProtocolName();
	std::wstring GetKeyExchange();
	std::wstring GetCipherName();
	std::wstring GetMacName();
	int GetAlgorithmWarnings();

	bool ResumedSession() const;

	static std::string ListTlsCiphers(std::string const& priority);

	bool SetClientCertificate(fz::native_string const& keyfile, fz::native_string const& certs, fz::native_string const& password);

	static std::wstring GetGnutlsVersion();
private:
	virtual void operator()(fz::event_base const& ev) override;

	friend class CTlsSocketImpl;
	std::unique_ptr<CTlsSocketImpl> impl_;
};

#endif
