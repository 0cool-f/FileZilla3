#include <filezilla.h>
#include "filezillaapp.h"
#include "verifycertdialog.h"
#include "dialogex.h"
#include "ipcmutex.h"
#include "Options.h"
#include "timeformatting.h"
#include "xrc_helper.h"

#include <libfilezilla/iputils.hpp>

#include <wx/scrolwin.h>
#include <wx/statbox.h>

CertStore::CertStore()
	: m_xmlFile(wxGetApp().GetSettingsFile(L"trustedcerts"))
{
}

bool CertStore::IsTrusted(fz::tls_session_info const& info)
{
	if (info.GetAlgorithmWarnings() != 0) {
		// These certs are never trusted.
		return false;
	}

	LoadTrustedCerts();

	fz::x509_certificate cert = info.GetCertificates()[0];

	return IsTrusted(info.GetHost(), info.GetPort(), cert.GetRawData(), false, !info.MismatchedHostname());
}

bool CertStore::IsInsecure(std::string const& host, unsigned int port, bool permanentOnly)
{
	auto const t = std::make_tuple(host, port);
	if (!permanentOnly && sessionInsecureHosts_.find(t) != sessionInsecureHosts_.cend()) {
		return true;
	}

	LoadTrustedCerts();

	if (insecureHosts_.find(t) != insecureHosts_.cend()) {
		return true;
	}

	return false;
}

bool CertStore::HasCertificate(std::string const& host, unsigned int port)
{
	for (auto const& cert : sessionTrustedCerts_) {
		if (cert.host == host && cert.port == port) {
			return true;
		}
	}

	LoadTrustedCerts();

	for (auto const& cert : trustedCerts_) {
		if (cert.host == host && cert.port == port) {
			return true;
		}
	}

	return false;
}

bool CertStore::DoIsTrusted(std::string const& host, unsigned int port, std::vector<uint8_t> const& data, std::list<CertStore::t_certData> const& trustedCerts, bool allowSans)
{
	if (!data.size()) {
		return false;
	}

	bool const dnsname = fz::get_address_type(host) == fz::address_type::unknown;
	
	for (auto const& cert : trustedCerts) {
		if (port != cert.port) {
			continue;
		}

		if (cert.data != data) {
			continue;
		}

		if (host != cert.host) {
			if (!dnsname || !allowSans || !cert.trustSans) {
				continue;
			}
		}

		return true;
	}

	return false;
}

bool CertStore::IsTrusted(std::string const& host, unsigned int port, std::vector<uint8_t> const& data, bool permanentOnly, bool allowSans)
{
	bool trusted = DoIsTrusted(host, port, data, trustedCerts_, allowSans);
	if (!trusted && !permanentOnly) {
		trusted = DoIsTrusted(host, port, data, sessionTrustedCerts_, allowSans);
	}

	return trusted;
}

void CertStore::LoadTrustedCerts()
{
	CReentrantInterProcessMutexLocker mutex(MUTEX_TRUSTEDCERTS);
	if (!m_xmlFile.Modified()) {
		return;
	}

	auto root = m_xmlFile.Load();
	if (!root) {
		return;
	}

	insecureHosts_.clear();
	trustedCerts_.clear();

	pugi::xml_node element;

	bool modified = false;
	if ((element = root.child("TrustedCerts"))) {

		auto const processEntry = [&](pugi::xml_node const& cert)
		{
			std::wstring value = GetTextElement(cert, "Data");

			t_certData data;
			data.data = fz::hex_decode(value);
			if (data.data.empty()) {
				return false;
			}

			data.host = cert.child_value("Host");
			data.port = GetTextElementInt(cert, "Port");
			if (data.host.empty() || data.port < 1 || data.port > 65535) {
				return false;
			}

			fz::datetime const now = fz::datetime::now();
			int64_t activationTime = GetTextElementInt(cert, "ActivationTime", 0);
			if (activationTime == 0 || activationTime > now.get_time_t()) {
				return false;
			}

			int64_t expirationTime = GetTextElementInt(cert, "ExpirationTime", 0);
			if (expirationTime == 0 || expirationTime < now.get_time_t()) {
				return false;
			}

			data.trustSans = GetTextElementBool(cert, "TrustSANs");

			// Weed out duplicates
			if (IsTrusted(data.host, data.port, data.data, true, false)) {
				return false;
			}

			trustedCerts_.emplace_back(std::move(data));

			return true;
		};

		auto cert = element.child("Certificate");
		while (cert) {

			auto nextCert = cert.next_sibling("Certificate");
			if (!processEntry(cert)) {
				modified = true;
				element.remove_child(cert);
			}
			cert = nextCert;
		}
	}

	if ((element = root.child("InsecureHosts"))) {

		auto const processEntry = [&](pugi::xml_node const& node)
		{
			std::string host = node.value();
			unsigned int port = node.attribute("Port").as_uint();
			if (host.empty() || port < 1 || port > 65535) {
				return false;
			}

			for (auto const& cert : trustedCerts_) {
				// A host can't be both trusted and insecure
				if (cert.host == host && cert.port == port) {
					return false;
				}
			}

			insecureHosts_.emplace(std::make_tuple(host, port));

			return true;
		};

		auto host = element.child("Host");
		while (host) {

			auto nextHost = host.next_sibling("Host");
			if (!processEntry(host)) {
				modified = true;
				element.remove_child(host);
			}
			host = nextHost;
		}
	}

	if (modified) {
		m_xmlFile.Save(false);
	}
}

void CertStore::SetInsecure(std::string const& host, unsigned int port, bool permanent)
{
	// A host can't be both trusted and insecure
	sessionTrustedCerts_.erase(
		std::remove_if(sessionTrustedCerts_.begin(), sessionTrustedCerts_.end(), [&host, &port](t_certData const& cert) { return cert.host == host && cert.port == port; }),
		sessionTrustedCerts_.end()
	);

	if (!permanent) {
		sessionInsecureHosts_.emplace(std::make_tuple(host, port));
		return;
	}

	CReentrantInterProcessMutexLocker mutex(MUTEX_TRUSTEDCERTS);
	LoadTrustedCerts();

	if (IsInsecure(host, port, true)) {
		return;
	}

	if (COptions::Get()->GetOptionVal(OPTION_DEFAULT_KIOSKMODE) != 2) {
		auto root = m_xmlFile.GetElement();
		if (root) {
			auto certs = root.child("TrustedCerts");

			// Purge certificates for this host
			auto const processEntry = [&host, &port](pugi::xml_node const& cert)
			{
				return host != cert.child_value("Host") || port != GetTextElementInt(cert, "Port");
			};

			auto cert = certs.child("Certificate");
			while (cert) {
				auto nextCert = cert.next_sibling("Certificate");
				if (!processEntry(cert)) {
					certs.remove_child(cert);
				}
				cert = nextCert;
			}

			auto insecureHosts = root.child("InsecureHosts");
			if (!insecureHosts) {
				insecureHosts = root.append_child("InsecureHosts");
			}

			// Remember host as insecure
			auto xhost = insecureHosts.append_child("Host");
			xhost.append_attribute("Port").set_value(port);
			xhost.text().set(fz::to_utf8(host).c_str());

			m_xmlFile.Save(true);
		}
	}

	// A host can't be both trusted and insecure
	trustedCerts_.erase(
		std::remove_if(trustedCerts_.begin(), trustedCerts_.end(), [&host, &port](t_certData const& cert) { return cert.host == host && cert.port == port; }),
		trustedCerts_.end()
	);

	insecureHosts_.emplace(std::make_tuple(host, port));
}

void CertStore::SetTrusted(fz::tls_session_info const& info, bool permanent, bool trustAllHostnames)
{
	const fz::x509_certificate certificate = info.GetCertificates()[0];

	t_certData cert;
	cert.host = info.GetHost();
	cert.port = info.GetPort();
	cert.data = certificate.GetRawData();

	if (trustAllHostnames) {
		cert.trustSans = true;
	}

	// A host can't be both trusted and insecure
	sessionInsecureHosts_.erase(std::make_tuple(cert.host, cert.port));

	if (!permanent) {
		t_certData cert;
		sessionTrustedCerts_.emplace_back(std::move(cert));

		return;
	}

	CReentrantInterProcessMutexLocker mutex(MUTEX_TRUSTEDCERTS);
	LoadTrustedCerts();

	if (IsTrusted(cert.host, cert.port, cert.data, true, false)) {
		return;
	}

	if (COptions::Get()->GetOptionVal(OPTION_DEFAULT_KIOSKMODE) != 2) {
		auto root = m_xmlFile.GetElement();
		if (root) {
			auto certs = root.child("TrustedCerts");
			if (!certs) {
				certs = root.append_child("TrustedCerts");
			}

			auto xCert = certs.append_child("Certificate");
			AddTextElementUtf8(xCert, "Data", fz::hex_encode<std::string>(cert.data));
			AddTextElement(xCert, "ActivationTime", static_cast<int64_t>(certificate.GetActivationTime().get_time_t()));
			AddTextElement(xCert, "ExpirationTime", static_cast<int64_t>(certificate.GetExpirationTime().get_time_t()));
			AddTextElement(xCert, "Host", cert.host);
			AddTextElement(xCert, "Port", cert.port);
			AddTextElement(xCert, "TrustSANs", cert.trustSans ? L"1" : L"0");

			// Purge insecure host
			auto const processEntry = [&cert](pugi::xml_node const& xhost)
			{
				return cert.host != GetTextElement(xhost) || cert.port != xhost.attribute("Port").as_uint();
			};

			auto insecureHosts = root.child("InsecureHosts");
			auto xhost = insecureHosts.child("Host");
			while (xhost) {

				auto nextHost = xhost.next_sibling("Host");
				if (!processEntry(xhost)) {
					insecureHosts.remove_child(xhost);
				}
				xhost = nextHost;
			}

			m_xmlFile.Save(true);
		}
	}

	// A host can't be both trusted and insecure
	insecureHosts_.erase(std::make_tuple(cert.host, cert.port));

	trustedCerts_.emplace_back(std::move(cert));
}




CVerifyCertDialog::CVerifyCertDialog(CertStore & certStore)
	: certStore_(certStore)
{
}


bool CVerifyCertDialog::DisplayCert(wxDialogEx* pDlg, fz::x509_certificate const& cert)
{
	bool warning = false;
	if (!cert.GetActivationTime().empty()) {
		if (cert.GetActivationTime() > fz::datetime::now()) {
			pDlg->SetChildLabel(XRCID("ID_ACTIVATION_TIME"), wxString::Format(_("%s - Not yet valid!"), CTimeFormat::Format(cert.GetActivationTime())));
			xrc_call(*pDlg, "ID_ACTIVATION_TIME", &wxWindow::SetForegroundColour, wxColour(255, 0, 0));
			warning = true;
		}
		else {
			pDlg->SetChildLabel(XRCID("ID_ACTIVATION_TIME"), CTimeFormat::Format(cert.GetActivationTime()));
			xrc_call(*pDlg, "ID_ACTIVATION_TIME", &wxWindow::SetForegroundColour, wxColour());
		}
	}
	else {
		warning = true;
		pDlg->SetChildLabel(XRCID("ID_ACTIVATION_TIME"), _("Invalid date"));
	}

	if (!cert.GetExpirationTime().empty()) {
		if (cert.GetExpirationTime() < fz::datetime::now()) {
			pDlg->SetChildLabel(XRCID("ID_EXPIRATION_TIME"), wxString::Format(_("%s - Certificate expired!"), CTimeFormat::Format(cert.GetExpirationTime())));
			xrc_call(*pDlg, "ID_EXPIRATION_TIME", &wxWindow::SetForegroundColour, wxColour(255, 0, 0));
			warning = true;
		}
		else {
			pDlg->SetChildLabel(XRCID("ID_EXPIRATION_TIME"), CTimeFormat::Format(cert.GetExpirationTime()));
			xrc_call(*pDlg, "ID_EXPIRATION_TIME", &wxWindow::SetForegroundColour, wxColour());
		}
	}
	else {
		warning = true;
		pDlg->SetChildLabel(XRCID("ID_EXPIRATION_TIME"), _("Invalid date"));
	}

	if (!cert.GetSerial().empty()) {
		pDlg->SetChildLabel(XRCID("ID_SERIAL"), fz::to_wstring_from_utf8(cert.GetSerial()));
	}
	else {
		pDlg->SetChildLabel(XRCID("ID_SERIAL"), _("None"));
	}

	pDlg->SetChildLabel(XRCID("ID_PKALGO"), wxString::Format(_("%s with %d bits"), fz::to_wstring_from_utf8(cert.GetPkAlgoName()), cert.GetPkAlgoBits()));
	pDlg->SetChildLabel(XRCID("ID_SIGNALGO"), fz::to_wstring_from_utf8(cert.GetSignatureAlgorithm()));

	wxString const sha256 = fz::to_wstring_from_utf8(cert.GetFingerPrintSHA256());
	pDlg->SetChildLabel(XRCID("ID_FINGERPRINT_SHA256"), sha256.Left(sha256.size() / 2 + 1) + L"\n" + sha256.Mid(sha256.size() / 2 + 1));
	pDlg->SetChildLabel(XRCID("ID_FINGERPRINT_SHA1"), fz::to_wstring_from_utf8(cert.GetFingerPrintSHA1()));

	ParseDN(XRCCTRL(*pDlg, "ID_ISSUER_BOX", wxStaticBox), fz::to_wstring_from_utf8(cert.GetIssuer()), m_pIssuerSizer);

	auto subjectPanel = XRCCTRL(*pDlg, "ID_SUBJECT_PANEL", wxScrolledWindow);
	subjectPanel->Freeze();

	ParseDN(subjectPanel, fz::to_wstring_from_utf8(cert.GetSubject()), m_pSubjectSizer);

	auto const& altNames = cert.GetAltSubjectNames();
	if (!altNames.empty()) {
		wxString str;
		for (auto const& altName : altNames) {
			str += LabelEscape(fz::to_wstring_from_utf8(altName.name)) + L"\n";
		}
		str.RemoveLast();
		m_pSubjectSizer->Add(new wxStaticText(subjectPanel, wxID_ANY, wxPLURAL("Alternative name:", "Alternative names:", altNames.size())));
		m_pSubjectSizer->Add(new wxStaticText(subjectPanel, wxID_ANY, str));
	}
	m_pSubjectSizer->Fit(subjectPanel);

	wxSize min = m_pSubjectSizer->CalcMin();
	int const maxHeight = (line_height_ + m_pDlg->ConvertDialogToPixels(wxPoint(0, 1)).y) * 15;
	if (min.y >= maxHeight) {
		min.y = maxHeight;
		min.x += wxSystemSettings::GetMetric(wxSYS_VSCROLL_X);
	}

	// Add extra safety margin to prevent squishing on OS X.
	min.x += 2;

	subjectPanel->SetMinSize(min);
	subjectPanel->Thaw();

	return warning;
}

#include <wx/scrolwin.h>

bool CVerifyCertDialog::DisplayAlgorithm(int controlId, std::string const& name, bool insecure)
{
	wxString wname = fz::to_wstring_from_utf8(name);
	if (insecure) {
		wname += L" - ";
		wname += _("Insecure algorithm!");

		auto wnd = m_pDlg->FindWindow(controlId);
		if (wnd) {
			wnd->SetForegroundColour(wxColour(255, 0, 0));
		}
	}

	m_pDlg->SetChildLabel(controlId, wname);

	return insecure;
}

void CVerifyCertDialog::ShowVerificationDialog(CCertificateNotification& notification, bool displayOnly)
{
	fz::tls_session_info& info = notification.info_;

	m_pDlg = new wxDialogEx;
	if (!m_pDlg->Load(0, L"ID_VERIFYCERT")) {
		wxBell();
		delete m_pDlg;
		m_pDlg = 0;
		return;
	}

	if (displayOnly) {
		xrc_call(*m_pDlg, "ID_DESC", &wxWindow::Hide);
		xrc_call(*m_pDlg, "ID_ALWAYS_DESC", &wxWindow::Hide);
		xrc_call(*m_pDlg, "ID_ALWAYS", &wxWindow::Hide);
		xrc_call(*m_pDlg, "ID_TRUST_SANS", &wxWindow::Hide);
		xrc_call(*m_pDlg, "wxID_CANCEL", &wxWindow::Hide);
		m_pDlg->SetTitle(L"Certificate details");
	}
	else {
		m_pDlg->WrapText(m_pDlg, XRCID("ID_DESC"), 420);

		if (COptions::Get()->GetOptionVal(OPTION_DEFAULT_KIOSKMODE) == 2) {
			XRCCTRL(*m_pDlg, "ID_ALWAYS", wxCheckBox)->Hide();
		}
	}

	m_certificates = info.GetCertificates();
	if (m_certificates.size() == 1) {
		XRCCTRL(*m_pDlg, "ID_CHAIN_DESC", wxStaticText)->Hide();
		XRCCTRL(*m_pDlg, "ID_CHAIN", wxChoice)->Hide();
	}
	else {
		wxChoice* pChoice = XRCCTRL(*m_pDlg, "ID_CHAIN", wxChoice);
		for (unsigned int i = 0; i < m_certificates.size(); ++i) {
			pChoice->Append(wxString::Format(L"%d", i));
		}
		pChoice->SetSelection(0);

		pChoice->Connect(wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler(CVerifyCertDialog::OnCertificateChoice), 0, this);
	}

	if (info.MismatchedHostname()) {
		xrc_call(*m_pDlg, "ID_HOST", &wxWindow::SetForegroundColour, wxColour(255, 0, 0));
		m_pDlg->SetChildLabel(XRCID("ID_HOST"), wxString::Format(_("%s:%d - Hostname does not match certificate"), LabelEscape(fz::to_wstring_from_utf8(info.GetHost())), info.GetPort()));
	}
	else {
		m_pDlg->SetChildLabel(XRCID("ID_HOST"), wxString::Format(L"%s:%d", LabelEscape(fz::to_wstring_from_utf8(info.GetHost())), info.GetPort()));
	}

	line_height_ = XRCCTRL(*m_pDlg, "ID_SUBJECT_DUMMY", wxStaticText)->GetSize().y;

	m_pSubjectSizer = XRCCTRL(*m_pDlg, "ID_SUBJECT_DUMMY", wxStaticText)->GetContainingSizer();
	m_pSubjectSizer->Clear(true);

	m_pIssuerSizer = XRCCTRL(*m_pDlg, "ID_ISSUER_DUMMY", wxStaticText)->GetContainingSizer();
	m_pIssuerSizer->Clear(true);

	wxSize minSize(0, 0);
	for (unsigned int i = 0; i < m_certificates.size(); ++i) {
		DisplayCert(m_pDlg, m_certificates[i]);
		m_pDlg->Layout();
		m_pDlg->GetSizer()->Fit(m_pDlg);
		minSize.IncTo(m_pDlg->GetSizer()->GetMinSize());
	}
	m_pDlg->GetSizer()->SetMinSize(minSize);

	bool warning = DisplayCert(m_pDlg, m_certificates[0]);

	DisplayAlgorithm(XRCID("ID_PROTOCOL"), info.GetProtocol(), (info.GetAlgorithmWarnings() & fz::tls_session_info::tlsver) != 0);
	DisplayAlgorithm(XRCID("ID_KEYEXCHANGE"), info.GetKeyExchange(), (info.GetAlgorithmWarnings() & fz::tls_session_info::kex) != 0);
	DisplayAlgorithm(XRCID("ID_CIPHER"), info.GetSessionCipher(), (info.GetAlgorithmWarnings() & fz::tls_session_info::cipher) != 0);
	DisplayAlgorithm(XRCID("ID_MAC"), info.GetSessionMac(), (info.GetAlgorithmWarnings() & fz::tls_session_info::mac) != 0);

	if (info.GetAlgorithmWarnings() != 0) {
		warning = true;
	}

	if (warning) {
		XRCCTRL(*m_pDlg, "ID_IMAGE", wxStaticBitmap)->SetBitmap(wxArtProvider::GetBitmap(wxART_WARNING));
		XRCCTRL(*m_pDlg, "ID_ALWAYS", wxCheckBox)->Enable(false);
	}

	bool const dnsname = fz::get_address_type(info.GetHost()) == fz::address_type::unknown;
	bool const sanTrustAllowed = !warning && dnsname && !info.MismatchedHostname();
	XRCCTRL(*m_pDlg, "ID_TRUST_SANS", wxCheckBox)->Enable(sanTrustAllowed);

	if (sanTrustAllowed && info.SystemTrust()) {
		xrc_call(*m_pDlg, "ID_ALWAYS", &wxCheckBox::SetValue, true);
		xrc_call(*m_pDlg, "ID_TRUST_SANS", &wxCheckBox::SetValue, true);
	}

	m_pDlg->GetSizer()->Fit(m_pDlg);
	m_pDlg->GetSizer()->SetSizeHints(m_pDlg);

	int res = m_pDlg->ShowModal();

	if (!displayOnly) {
		if (res == wxID_OK) {
			notification.trusted_ = true;

			if (!info.GetAlgorithmWarnings()) {
				bool trustSANs = sanTrustAllowed && xrc_call(*m_pDlg, "ID_TRUST_SANS", &wxCheckBox::GetValue);
				bool permanent = !warning && xrc_call(*m_pDlg, "ID_ALWAYS", &wxCheckBox::GetValue);
				certStore_.SetTrusted(info, permanent, trustSANs);
			}
		}
		else {
			notification.trusted_ = false;
		}
	}

	delete m_pDlg;
	m_pDlg = 0;
}

namespace {
std::vector<std::pair<std::wstring, std::wstring>> dn_split(std::wstring const& dn)
{
	std::vector<std::pair<std::wstring, std::wstring>> ret;

	std::wstring type;
	std::wstring value;

	int escaping{};
	bool phase{};

	for (auto const& c : dn) {
		auto& out = phase ? value : type;
		if (escaping) {
			if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				--escaping;
			}
			else {
				escaping = 0;
			}
			out += c;
		}
		else if (!phase && c == '=') {
			phase = true;
		}
		else if (c == '+' || c == ',') {
			if (!type.empty() && !value.empty()) {
				ret.emplace_back(type, value);
			}
			type.clear();
			value.clear();
			phase = false;
		}
		else if (c == '\\') {
			out += c;
			escaping = 2;
		}
		else {
			out += c;
		}
	}

	if (!type.empty() && !value.empty()) {
		ret.emplace_back(type, value);
	}

	return ret;
}
}


void CVerifyCertDialog::ParseDN(wxWindow* parent, std::wstring const& dn, wxSizer* pSizer)
{
	pSizer->Clear(true);

	auto tokens = dn_split(dn);

	ParseDN_by_prefix(parent, tokens, L"CN", _("Common name:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"O", _("Organization:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"businessCategory", _("Business category:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"OU", _("Unit:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"title", _("Title:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"C", _("Country:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"ST", _("State or province:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"L", _("Locality:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"postalCode", _("Postal code:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"street", _("Street:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"EMAIL", _("E-Mail:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"serialNumber", _("Serial number:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"telephoneNumber", _("Telephone number:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"name", _("Name:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"jurisdictionOfIncorporationCountryName", _("Jurisdiction country:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"jurisdictionOfIncorporationStateOrProvinceName", _("Jurisdiction state or province:"), pSizer);
	ParseDN_by_prefix(parent, tokens, L"jurisdictionOfIncorporationLocalityName", _("Jurisdiction locality:"), pSizer);

	if (!tokens.empty()) {
		std::wstring other;
		for (auto const& pair : tokens) {
			if (!other.empty()) {
				other += ',';
			}
			other += pair.first;
			other += '=';
			other += pair.second;
		}

		pSizer->Add(new wxStaticText(parent, wxID_ANY, _("Other:")));
		pSizer->Add(new wxStaticText(parent, wxID_ANY, LabelEscape(other)));
	}
}

void CVerifyCertDialog::ParseDN_by_prefix(wxWindow* parent, std::vector<std::pair<std::wstring, std::wstring>> & tokens, std::wstring const& prefix, wxString const& name, wxSizer* pSizer)
{
	std::wstring value;

	for (auto it = tokens.cbegin(); it != tokens.cend(); ) {
		auto& pair = *it;
		if (!fz::equal_insensitive_ascii(pair.first, prefix)) {
			++it;
			continue;
		}

		if (!value.empty()) {
			value += '\n';
		}
		value += pair.second;

		it = tokens.erase(it);
	}

	if (!value.empty()) {
		pSizer->Add(new wxStaticText(parent, wxID_ANY, name));
		pSizer->Add(new wxStaticText(parent, wxID_ANY, LabelEscape(value)));
	}
}

void CVerifyCertDialog::OnCertificateChoice(wxCommandEvent& event)
{
	int sel = event.GetSelection();
	if (sel < 0 || static_cast<unsigned int>(sel) > m_certificates.size()) {
		return;
	}
	DisplayCert(m_pDlg, m_certificates[sel]);

	m_pDlg->Layout();
	m_pDlg->GetSizer()->Fit(m_pDlg);
	m_pDlg->Refresh();
}


void ConfirmInsecureConection(CertStore & certStore, CInsecureFTPNotification & notification)
{
	wxDialogEx dlg;
	dlg.Create(0, wxID_ANY, _("Insecure FTP connection"));

	auto const& lay = dlg.layout();
	auto outer = new wxBoxSizer(wxVERTICAL);
	dlg.SetSizer(outer);

	auto main = lay.createFlex(1);
	outer->Add(main, 0, wxALL, lay.border);

	bool const warning = certStore.HasCertificate(fz::to_utf8(notification.server_.GetHost()), notification.server_.GetPort());

	if (warning) {
		main->Add(new wxStaticText(&dlg, -1, _("Warning! You have previously connected to this server using FTP over TLS, yet the server has now rejected FTP over TLS.")));
		main->Add(new wxStaticText(&dlg, -1, _("This may be the result of a downgrade attack, only continue after you have spoken to the server administrator or server hosting provider.")));
	}
	else {
		main->Add(new wxStaticText(&dlg, -1, _("This server does not support FTP over TLS.")));
	}
	main->Add(new wxStaticText(&dlg, -1, _("If you continue, your password and files will be sent in clear over the internet.")));


	auto flex = lay.createFlex(2);
	main->Add(flex, 0, wxALL, lay.border);
	flex->Add(new wxStaticText(&dlg, -1, _("Host:")), lay.valign);
	flex->Add(new wxStaticText(&dlg, -1, LabelEscape(notification.server_.GetHost())), lay.valign);
	flex->Add(new wxStaticText(&dlg, -1, _("Port:")), lay.valign);
	flex->Add(new wxStaticText(&dlg, -1, fz::to_wstring(notification.server_.GetPort())), lay.valign);

	auto always = new wxCheckBox(&dlg, -1, _("&Always allow insecure plain FTP for this server."));
	main->Add(always);

	auto buttons = lay.createButtonSizer(&dlg, main, true);

	auto ok = new wxButton(&dlg, wxID_OK, _("&OK"));
	if (!warning) {
		ok->SetFocus();
		ok->SetDefault();
	}
	buttons->AddButton(ok);

	auto cancel = new wxButton(&dlg, wxID_CANCEL, _("&Cancel"));
	if (warning) {
		cancel->SetFocus();
		cancel->SetDefault();
	}
	buttons->AddButton(cancel);

	dlg.Bind(wxEVT_BUTTON, [&dlg](wxEvent & evt) {dlg.EndModal(evt.GetId()); });

	buttons->Realize();

	dlg.WrapRecursive(&dlg, 2);
	dlg.Layout();

	dlg.GetSizer()->Fit(&dlg);



	bool allow = dlg.ShowModal() == wxID_OK;
	if (allow) {
		notification.allow_ = true;

		certStore.SetInsecure(fz::to_utf8(notification.server_.GetHost()), notification.server_.GetPort(), always->GetValue());
	}
}
