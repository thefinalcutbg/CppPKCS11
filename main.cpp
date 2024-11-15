#include <iostream>
#include "PKCS11.h"

int main()
{
    PKCS11::setDriverPaths(
        {
            "C:/Windows/System32/eTPKCS11.dll",
            "C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll",
            "C:/Windows/System32/OcsPKCS11Wrapper.dll",
            "C:/Windows/System32/bit4ipki.dll"
        }
    );

    auto passCallback = [](const X509Details& certData) {

        std::cout << "Enter password for " << certData.name << ": ";

        std::string result;

        std::cin >> result;

        return result;
    };

    auto certListCallback = [](const std::vector<X509Details>& certList) {

        std::cout << "Select the certificate you want to use:" << std::endl;

        for (int i = 0; i < certList.size(); i++) {
            
            std::cout << std::to_string(i) << ". " << certList[i].name << std::endl;
        }

        int result = 0;

        std::cin >> result;

        return result;

    };

    PKCS11 pkcs(passCallback, certListCallback);// , certListCallback);

    auto state = pkcs.getState();

    switch (pkcs.getState())
    {
        case PKCS11::NoCertificate:
        case PKCS11::LoginAborted:
        case PKCS11::LoginFailed:
            std::cout << "Login failed";
            break;

        case PKCS11::AutoLoggedIn:
        case PKCS11::JustLoggedIn:
        {
            std::cout << "Login successful" << std::endl;
            x509_st* public_key = pkcs.x509ptr();
            evp_pkey_st* pkey = pkcs.takePrivateKey();
        }
        break;
    }

    return 0;

}