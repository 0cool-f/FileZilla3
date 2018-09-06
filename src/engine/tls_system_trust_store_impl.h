#ifndef FILEZILLA_ENGINE_TLS_SYSTEM_TRUST_STORE_IMPL_HEADER
#define FILEZILLA_ENGINE_TLS_SYSTEM_TRUST_STORE_IMPL_HEADER

#include "tls_system_trust_store.h"

#if defined(_MSC_VER)
typedef std::make_signed_t<size_t> ssize_t;
#endif

#include <gnutls/gnutls.h>


#include <libfilezilla/thread_pool.hpp>

#include <tuple>

class TlsSystemTrustStoreImpl
{
public:
	TlsSystemTrustStoreImpl(fz::thread_pool & pool);
	~TlsSystemTrustStoreImpl();

	std::tuple<gnutls_certificate_credentials_t, fz::scoped_lock> lease();

private:
	bool initialized_{};
	fz::mutex mtx_{ false };
	fz::condition cond_;

	gnutls_certificate_credentials_t credentials_{};

	fz::thread_pool& pool_;
	fz::async_task task_;
};

#endif
