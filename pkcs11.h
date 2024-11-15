#include <string>
#include <vector>
#include <functional>

struct x509_st;

struct X509Details
{
	X509Details(x509_st* x509, const std::string& driverPath);
	X509Details() {};

	std::string x509_pem;
	std::string name;
	std::string organization;
	std::string validFrom8601;
	std::string validTo8601;
	std::string driverPath;

	bool isValid() const;

	bool operator==(const X509Details& other) const {

		if (x509_pem.empty()) return false;

		return x509_pem == other.x509_pem;
	}

	bool operator!=(const X509Details& other) const {
		return !(*this == other);
	}
};

struct evp_pkey_st;
struct PKCS11_slot_st;
struct PKCS11_cert_st;

class PKCS11
{

public:
	enum State { 
		NoCertificate, //no certificate has been loaded - public and private keys will be null
		NoCertificateChosen, //among several certificates, none of them was chosen
		LoginAborted, //user-provided pass was empty
		LoginFailed, //wrong password or locked smart card
		JustLoggedIn, //logging in for a first time after the smart card has been plugged in
		AutoLoggedIn //the card has already been unlocked
	};

private:
	unsigned int nslots{ 0 };
	PKCS11_slot_st* pslots{ nullptr };
	PKCS11_slot_st* current_slot{ nullptr };

	X509Details m_cert_details;
	PKCS11_cert_st* m_certificate{ nullptr };
	evp_pkey_st* m_prv_key{ nullptr };
	bool prv_key_owned = true;

	State m_state{ NoCertificate };

	PKCS11_cert_st* loadCertificate(const X509Details& cert);

	static std::vector<X509Details> getCertList(bool returnFirst);

public:
	//Constructor takmes the password callback and the callback for chosing a certificate if more than one are found
	//If the certificate callback isnt provided the object is initialized with the first found certificate
	PKCS11(
		std::function<std::string(const X509Details& data)> passCallback,
		std::function<int(const std::vector<X509Details>& certList)> certCallback = nullptr
	);

	PKCS11::State getState() const { return m_state; }

	const std::string& pem_x509cert() const { return m_cert_details.x509_pem; }
	x509_st* x509ptr();

	//taking ownership of the private key doesn't call the free functions in destructor
	evp_pkey_st* takePrivateKey(bool takeOnwership = false);

	//can set multiple driver paths
	static void setDriverPaths(const std::vector<std::string>& driverPaths);

	static void cleanup();

	~PKCS11();
};