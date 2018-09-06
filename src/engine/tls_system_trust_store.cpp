#include <filezilla.h>

#include "tls_system_trust_store.h"
#include "tls_system_trust_store_impl.h"

TlsSystemTrustStoreImpl::TlsSystemTrustStoreImpl(fz::thread_pool & pool)
	: pool_(pool)
{
	fz::scoped_lock l(mtx_);
	task_ = pool_.spawn([this]() {
		gnutls_certificate_credentials_t cred{};

		if (gnutls_certificate_allocate_credentials(&cred) >= 0) {
			if (gnutls_certificate_set_x509_system_trust(cred) < 0) {
				gnutls_certificate_free_credentials(cred);
				cred = nullptr;
			}
		}

		fz::scoped_lock l(mtx_);
		initialized_ = true;
		credentials_ = cred;
		cond_.signal(l);
	});
}

TlsSystemTrustStoreImpl::~TlsSystemTrustStoreImpl()
{
	task_.join();

	gnutls_certificate_free_credentials(credentials_);
}

std::tuple<gnutls_certificate_credentials_t, fz::scoped_lock> TlsSystemTrustStoreImpl::lease()
{
	fz::scoped_lock l(mtx_);
	if (!initialized_) {
		cond_.wait(l);
		task_.join();
	}

	return std::make_tuple(credentials_, std::move(l));
}


TlsSystemTrustStore::TlsSystemTrustStore(fz::thread_pool & pool)
	: impl_(std::make_unique<TlsSystemTrustStoreImpl>(pool))
{
}

TlsSystemTrustStore::~TlsSystemTrustStore()
{
}
