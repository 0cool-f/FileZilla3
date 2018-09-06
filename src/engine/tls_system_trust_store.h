#ifndef FILEZILLA_ENGINE_TLS_SYSTEM_TRUST_STORE_HEADER
#define FILEZILLA_ENGINE_TLS_SYSTEM_TRUST_STORE_HEADER

class TlsSystemTrustStoreImpl;

namespace fz {
class thread_pool;
}

#include <memory>

// Loading system trust store can take a significant amount of time
// if there are large CRLs.
// Use it as shared resource that is loaded asynchronously
class TlsSystemTrustStore final
{
public:
	TlsSystemTrustStore(fz::thread_pool & pool);
	~TlsSystemTrustStore();

private:
	friend class CTlsSocketImpl;
	std::unique_ptr<TlsSystemTrustStoreImpl> impl_;
};

#endif
