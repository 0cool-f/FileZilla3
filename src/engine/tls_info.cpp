#include <filezilla.h>

#include "tls_info.h"

namespace fz {
x509_certificate::x509_certificate(
		std::vector<uint8_t> const& rawData,
		fz::datetime const& activation_time, fz::datetime const& expiration_time,
		std::string const& serial,
		std::string const& pkalgoname, unsigned int bits,
		std::string const& signalgoname,
		std::string const& fingerprint_sha256,
		std::string const& fingerprint_sha1,
		std::string const& issuer,
		std::string const& subject,
		std::vector<SubjectName> const& altSubjectNames)
	: activation_time_(activation_time)
	, expiration_time_(expiration_time)
	, raw_cert_(rawData)
	, serial_(serial)
	, pkalgoname_(pkalgoname)
	, pkalgobits_(bits)
	, signalgoname_(signalgoname)
	, fingerprint_sha256_(fingerprint_sha256)
	, fingerprint_sha1_(fingerprint_sha1)
	, issuer_(issuer)
	, subject_(subject)
	, alt_subject_names_(altSubjectNames)
{
}

x509_certificate::x509_certificate(
	std::vector<uint8_t> && rawData,
	fz::datetime const& activation_time, fz::datetime const& expiration_time,
	std::string const& serial,
	std::string const& pkalgoname, unsigned int bits,
	std::string const& signalgoname,
	std::string const& fingerprint_sha256,
	std::string const& fingerprint_sha1,
	std::string const& issuer,
	std::string const& subject,
	std::vector<SubjectName> && altSubjectNames)
	: activation_time_(activation_time)
	, expiration_time_(expiration_time)
	, raw_cert_(rawData)
	, serial_(serial)
	, pkalgoname_(pkalgoname)
	, pkalgobits_(bits)
	, signalgoname_(signalgoname)
	, fingerprint_sha256_(fingerprint_sha256)
	, fingerprint_sha1_(fingerprint_sha1)
	, issuer_(issuer)
	, subject_(subject)
	, alt_subject_names_(altSubjectNames)
{
}

tls_session_info::tls_session_info(std::string const& host, unsigned int port,
		std::string const& protocol,
		std::string const& key_exchange,
		std::string const& session_cipher,
		std::string const& session_mac,
		int algorithm_warnings,
		std::vector<fz::x509_certificate> && certificates,
		bool system_trust,
		bool hostname_mismatch)
	: host_(host)
	, port_(port)
	, protocol_(protocol)
	, key_exchange_(key_exchange)
	, session_cipher_(session_cipher)
	, session_mac_(session_mac)
	, algorithm_warnings_(algorithm_warnings)
	, certificates_(certificates)
	, system_trust_(system_trust)
	, hostname_mismatch_(hostname_mismatch)
{
}
}
