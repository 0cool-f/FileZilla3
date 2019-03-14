#ifndef FILEZILLA_ENGINE_TLSSOCKET_HEADER
#define FILEZILLA_ENGINE_TLSSOCKET_HEADER

#include "backend.h"

class CControlSocket;
class CTlsSocketImpl;

class CTlsSocket final : protected fz::event_handler, public SocketLayer
{
public:
	CTlsSocket(fz::event_handler* pEvtHandler, fz::socket_interface& layer, CControlSocket* pOwner);
	virtual ~CTlsSocket();

	int Handshake(const CTlsSocket* pPrimarySocket = nullptr, bool try_resume = 0);

	virtual int read(void *buffer, unsigned int size, int& error) override;
	virtual int write(const void *buffer, unsigned int size, int& error) override;

	int Shutdown(bool silenceReadErrors);

	void TrustCurrentCert(bool trusted);

	fz::socket_state get_state() const;

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
