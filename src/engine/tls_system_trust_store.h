#ifndef FILEZILLA_ENGINE_TLS_SYSTEM_TRUST_STORE_HEADER
#define FILEZILLA_ENGINE_TLS_SYSTEM_TRUST_STORE_HEADER

/** \file
 * \brief System trust store for TLS certificates
 *
 * Declares the \ref fz::tls_system_trust_store class.
 */

#include <memory>

namespace fz {
class thread_pool;
class tls_system_trust_store_impl;

/**
 * Loading system trust store can take a significant amount of time
 * if there are large CRLs.
 * Use it as shared resource that is loaded asynchronously
 */
class tls_system_trust_store final
{
public:
	tls_system_trust_store(thread_pool& pool);
	~tls_system_trust_store();

private:
	friend class CTlsSocketImpl;
	std::unique_ptr<tls_system_trust_store_impl> impl_;
};
}

#endif
