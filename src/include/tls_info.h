#ifndef FILEZILLA_TLS_INFO_HEADER
#define FILEZILLA_TLS_INFO_HEADER

#include <libfilezilla/time.hpp>

namespace fz {
class x509_certificate final
{
public:
	class SubjectName final
	{
	public:
		std::string name;
		bool isDns{};
	};

	x509_certificate() = default;
	~x509_certificate() noexcept = default;
	x509_certificate(x509_certificate const&) = default;
	x509_certificate(x509_certificate&&) noexcept = default;
	x509_certificate& operator=(x509_certificate const&) = default;
	x509_certificate& operator=(x509_certificate&&) noexcept = default;

	x509_certificate(
		std::vector<uint8_t> const& rawData,
		fz::datetime const& activationTime, fz::datetime const& expirationTime,
		std::string const& serial,
		std::string const& pkalgoname, unsigned int bits,
		std::string const& signalgoname,
		std::string const& fingerprint_sha256,
		std::string const& fingerprint_sha1,
		std::string const& issuer,
		std::string const& subject,
		std::vector<SubjectName> const& altSubjectNames);

	x509_certificate(
		std::vector<uint8_t> && rawdata,
		fz::datetime const& activationTime, fz::datetime const& expirationTime,
		std::string const& serial,
		std::string const& pkalgoname, unsigned int bits,
		std::string const& signalgoname,
		std::string const& fingerprint_sha256,
		std::string const& fingerprint_sha1,
		std::string const& issuer,
		std::string const& subject,
		std::vector<SubjectName> && altSubjectNames);


	std::vector<uint8_t> GetRawData() const { return raw_cert_; }
	fz::datetime GetActivationTime() const { return activation_time_; }
	fz::datetime GetExpirationTime() const { return expiration_time_; }

	std::string const& GetSerial() const { return serial_; }
	std::string const& GetPkAlgoName() const { return pkalgoname_; }
	unsigned int GetPkAlgoBits() const { return pkalgobits_; }

	std::string const& GetSignatureAlgorithm() const { return signalgoname_; }

	std::string const& GetFingerPrintSHA256() const { return fingerprint_sha256_; }
	std::string const& GetFingerPrintSHA1() const { return fingerprint_sha1_; }

	std::string const& GetSubject() const { return subject_; }
	std::string const& GetIssuer() const { return issuer_; }

	std::vector<SubjectName> const& GetAltSubjectNames() const { return alt_subject_names_; }

	explicit operator bool() const { return !raw_cert_.empty(); }

private:
	fz::datetime activation_time_;
	fz::datetime expiration_time_;

	std::vector<uint8_t> raw_cert_;

	std::string serial_;
	std::string pkalgoname_;
	unsigned int pkalgobits_{};

	std::string signalgoname_;

	std::string fingerprint_sha256_;
	std::string fingerprint_sha1_;

	std::string issuer_;
	std::string subject_;

	std::vector<SubjectName> alt_subject_names_;
};

class tls_session_info final
{
public:
	tls_session_info() = default;
	~tls_session_info() = default;
	tls_session_info(tls_session_info const&) = default;
	tls_session_info(tls_session_info&&) noexcept = default;
	tls_session_info& operator=(tls_session_info const&) = default;
	tls_session_info& operator=(tls_session_info&&) noexcept = default;

	tls_session_info(std::string const& host, unsigned int port,
		std::string const& protocol,
		std::string const& key_exchange,
		std::string const& session_cipher,
		std::string const& session_mac,
		int algorithm_warnings,
		std::vector<x509_certificate>&& certificates,
		bool system_trust,
		bool hostname_mismatch);

	std::string const& GetHost() const { return host_; }
	unsigned int GetPort() const { return port_; }

	std::string const& GetSessionCipher() const { return session_cipher_; }
	std::string const& GetSessionMac() const { return session_mac_; }

	const std::vector<fz::x509_certificate> GetCertificates() const { return certificates_; }

	std::string const& GetProtocol() const { return protocol_; }
	std::string const& GetKeyExchange() const { return key_exchange_; }

	enum algorithm_warnings_t
	{
		tlsver = 1,
		cipher = 2,
		mac = 4,
		kex = 8
	};

	int GetAlgorithmWarnings() const { return algorithm_warnings_; }

	bool SystemTrust() const { return system_trust_; }
	bool MismatchedHostname() const { return hostname_mismatch_; }

private:
	std::string host_;
	unsigned int port_{};

	std::string protocol_;
	std::string key_exchange_;
	std::string session_cipher_;
	std::string session_mac_;
	int algorithm_warnings_{};

	std::vector<x509_certificate> certificates_;

	bool system_trust_{};
	bool hostname_mismatch_{};
};
}

#endif