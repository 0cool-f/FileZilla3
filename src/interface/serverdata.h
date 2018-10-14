#ifndef FILEZILLA_INTERFACE_SERVER_HEADER
#define FILEZILLA_INTERFACE_SERVER_HEADER

#include <server.h>

#include <libfilezilla/encryption.hpp>

#include <string>

class ProtectedCredentials final : public Credentials
{
public:
	ProtectedCredentials() = default;
	ProtectedCredentials(ProtectedCredentials const& c) = default;
	ProtectedCredentials& operator=(ProtectedCredentials const& c) = default;

	explicit ProtectedCredentials(Credentials const& c)
		: Credentials(c)
	{
	}

	void Protect();
	void Protect(fz::public_key const& key);
	bool Unprotect(fz::private_key const& key, bool on_failure_set_to_ask = false);

	fz::public_key encrypted_;

private:
	bool DoUnprotect(fz::private_key const& key);
};

class ServerWithCredentials final
{
public:
	ServerWithCredentials() = default;

	explicit ServerWithCredentials(CServer const& s, Credentials const& c)
		: server(s)
		, credentials(c)
	{}

	explicit ServerWithCredentials(CServer const& s, ProtectedCredentials const& c)
		: server(s)
		, credentials(c)
	{}

	// Return true if URL could be parsed correctly, false otherwise.
	// If parsing fails, pError is filled with the reason and the CServer instance may be left an undefined state.
	bool ParseUrl(std::wstring host, unsigned int port, std::wstring user, std::wstring pass, std::wstring &error, CServerPath &path, ServerProtocol const hint = UNKNOWN);
	bool ParseUrl(std::wstring const& host, std::wstring const& port, std::wstring const& user, std::wstring const& pass, std::wstring &error, CServerPath &path, ServerProtocol const hint = UNKNOWN);

	std::wstring Format(ServerFormat formatType) const {
		return server.Format(formatType, credentials);
	}

	void SetLogonType(LogonType logonType);

	void SetUser(std::wstring const& user);

	explicit operator bool() const {
		return static_cast<bool>(server);
	}

	bool operator==(ServerWithCredentials const& rhs) const {
		return server == rhs.server;
	}
	bool operator!=(ServerWithCredentials const& rhs) const {
		return !(*this == rhs);
	}

	CServer server;
	ProtectedCredentials credentials;
};

#endif
