#ifndef FILEZILLA_ENGINE_TLSSOCKET_HEADER
#define FILEZILLA_ENGINE_TLSSOCKET_HEADER

#include <libfilezilla/socket.hpp>

namespace fz {
class logger_interface;
class tls_system_trust_store;
class tls_session_info;

class tls_layer;
class tls_layer_impl;

struct certificate_verification_event_type;
typedef simple_event<certificate_verification_event_type, tls_layer*, tls_session_info> certificate_verification_event;

class tls_layer final : protected event_handler, public socket_layer
{
public:
	tls_layer(event_loop& event_loop, event_handler* evt_handler, socket_interface& layer, tls_system_trust_store * system_trust_store, logger_interface& logger);
	virtual ~tls_layer();

	/**
	 * \brief Starts shaking hand for a new TLS session as client.
	 *
	 * Returns true if the handshake has started, false on error.
	 *
	 * If the handshake is started, wait for a connection event for the result.
	 *
	 * The certificate negotiated that eventually gets negotiated for the session]
	 * must match the passed required_certificate, either in DER or PEM, 
	 * or the handshake will fail.
	 */
	bool client_handshake(std::vector<uint8_t> const& required_certificate, std::vector<uint8_t> const& session_to_resume = std::vector<uint8_t>(), native_string const& session_hostname = native_string());

	/**
	 * \brief Starts shaking hand for a new TLS session as client.
	 *
	 * Returns true if the handshake has started, false on error.
	 *
	 * If the handshake is started, wait for a connection event for the result.
	 *
	 * If a verification handler is passed, it will receive a 
	 * certificate_verification_event event upon which it must call
	 * set_verification_result.
	 * If no verification handler is passed, verification is done soley using the system
	 * trust store.
	 */
	bool client_handshake(event_handler *const verification_handler, std::vector<uint8_t> const& session_to_resume = std::vector<uint8_t>(), native_string const& session_hostname = native_string());

	/// Gets session parameters for resumption
	std::vector<uint8_t> get_session_parameters() const;

	/// Gets the session's certificate in DER
	std::vector<uint8_t> get_raw_certificate() const;

	virtual int connect(native_string const& host, unsigned int port, address_type family = address_type::unknown) override;

	virtual int read(void *buffer, unsigned int size, int& error) override;
	virtual int write(void const* buffer, unsigned int size, int& error) override;

	virtual int shutdown() override;

	void set_verification_result(bool trusted);

	virtual socket_state get_state() const override;

	std::string get_protocol() const;
	std::string get_key_exchange() const;
	std::string get_cipher() const;
	std::string get_mac() const;
	int get_algorithm_warnings() const;

	bool resumed_session() const;

	static std::string list_tls_ciphers(std::string const& priority);

	bool set_client_certificate(native_string const& keyfile, native_string const& certs, native_string const& password);

	static std::string get_gnutls_version();

private:
	virtual void operator()(event_base const& ev) override;

	friend class tls_layer_impl;
	std::unique_ptr<tls_layer_impl> impl_;
};
}

#endif
