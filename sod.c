// messy example, seed to solana wallet address
// based on https://www.abiraja.com/blog/from-seed-phrase-to-solana-address
// invpe 2k23
// g++ sod.c -lsodium -lssl -lcrypto
#include <string.h>
#include <sodium.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector> 
#include <openssl/sha.h>
#include <openssl/hmac.h>    
  
std::vector<std::string> split(const std::string& str, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0, end = 0;
    while ((end = str.find(delimiter, start)) != std::string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
    }
    tokens.push_back(str.substr(start));
    return tokens;
}
std::vector<unsigned char> mnemonicToSeed(const std::string& mnemonic, const std::string& password) 
{
    std::vector<std::string> words = split(mnemonic, " ");
    if (words.size() % 3 != 0 || words.size() < 12 || words.size() > 24) {
         throw std::invalid_argument("Invalid number of words");
    } 

    // Generate seed using PBKDF2 with HMAC-SHA512
    unsigned int seed_length = 64;
    std::vector<unsigned char> salt = std::vector<unsigned char>(password.begin(), password.end()); // "mnemonic" salt
    std::vector<unsigned char> seed(seed_length);
    PKCS5_PBKDF2_HMAC((const char*)mnemonic.data(), mnemonic.size(), salt.data(), salt.size(), 2048, EVP_sha512(), seed_length, seed.data());
    return seed;
} 
unsigned char* hmac_sha512(const unsigned char* key, int keylen,const unsigned char* data, int datalen,unsigned char* result, unsigned int* resultlen) {
    return HMAC(EVP_sha512(), key, keylen, data, datalen, result, resultlen);
}
std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
} 
//https://bitcoin.stackexchange.com/questions/76480/encode-decode-base-58-c
std::string b58(const char *priv_hex)
{
    char table[] = {'1','2','3','4','5','6','7','8','9','A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};

    BIGNUM *base58 = NULL;

    BIGNUM *resultExp = BN_new();
    BIGNUM *resultAdd = BN_new();
    BIGNUM *resultRem = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();

    BN_dec2bn(&base58, "58");

    std::string endresult;
    std::vector<int> v;

    BN_hex2bn( &resultAdd, priv_hex );

    while( !BN_is_zero(resultAdd) ) {
        BN_div(resultAdd, resultRem, resultAdd, base58, bn_ctx);
        char *asdf = BN_bn2dec(resultRem);
        v.push_back(atoi(asdf));
    }

    for (int i = (int)v.size()-1; i >= 0; i--) {
        endresult = endresult + table[v[i]];
    }

    BN_free(resultAdd);
    BN_free(resultExp);
    BN_free(resultRem);
    BN_CTX_free(bn_ctx);

    return endresult;
}
int main(int argc, char*argv[]) 
{
     
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
 

    // 1 Mnemonic to Seed
    std::string mnemonic = std::string(argv[1]); 
    std::cout << "Mnemonic: " << mnemonic << std::endl;
    std::string password = "mnemonic";
    std::vector<unsigned char> vseed = mnemonicToSeed(mnemonic, password);
    std::string seed_hex = bytesToHex(vseed);
    std::cout << "Seed (hex): " << seed_hex << std::endl;   
    unsigned char seed[vseed.size()];
    memcpy(seed,vseed.data(),vseed.size());  

 
    // Seed to BIP32 Master Private Key and Master Chain Code
    unsigned char generated_key_pair[64]; 
    const char* strKey = "ed25519 seed"; 
    hmac_sha512((const unsigned char*) strKey, 
        strlen(strKey), 
        vseed.data(), 
        vseed.size(), 
        generated_key_pair, 
        nullptr); 
 
    // The first 32 bytes of the result represent the master private key
    // and the second 32 bytes represent the chain code
    // We take the first 32 bytes as the master private key and the other 32 bytes are used later as the ‘chaincode’ to ‘extend’ the key when generating children key-pairs.
    unsigned char* master_priv_key_ptr = generated_key_pair;
    unsigned char* chain_code_ptr = generated_key_pair + 32;

    printf("M Priv Key: ");
    for(int i = 0; i < 32; i++) 
        printf("%x", master_priv_key_ptr[i]); 
    printf("\n");

    printf("M ChainCod: ");
    for(int i = 0; i < 32; i++) 
        printf("%x", chain_code_ptr[i]); 
    printf("\n");

   


  
    // 2  Master key → Wallet private key
    // Generate a keypair from the seed  
    std::vector<uint32_t> vPath; 
    vPath.push_back(44|0x80000000); // 44 | 0x80000000
    vPath.push_back(501|0x80000000); // 501 | 0x80000000 
    vPath.push_back(0|0x80000000); // 0 | 0x80000000 
    vPath.push_back(0|0x80000000); // 0 | 0x80000000  
    // Traverse the path
    unsigned char *pChainCodeToUse  = chain_code_ptr;  
    unsigned char *pMasterKeyToUse  = master_priv_key_ptr;

    for(int i = 0; i < vPath.size(); i++)
    { 
        printf("------%li------\n", vPath[i]);

        // DATA Buffer
        std::vector<unsigned char> vData; 

        // 0
        vData.push_back(0x00); 

        // Key - 32
        for(int a = 0; a < 32; a++)
            vData.push_back(pMasterKeyToUse[a]); 

        // Segment  
        uint32_t index =  vPath[i];
        std::vector<unsigned char> index_data(sizeof(index));
        for (size_t a = 0; a < sizeof(index); ++a) {
            index_data[sizeof(index) - a - 1] = (index >> (a * 8)) & 0xff;
        }  

        for(int a = 0; a < index_data.size(); a++) 
            vData.push_back(index_data[a]); 
             
        printf("Data: ");
        for(int a = 0; a < vData.size(); a++)
            printf("%02x", vData[a]);
        printf("\n");


        unsigned char uNewKey[64]; 
        hmac_sha512(pChainCodeToUse,32,
            vData.data(),vData.size(), 
            uNewKey, nullptr); 

        // Split
        pMasterKeyToUse = uNewKey;
        pChainCodeToUse = uNewKey + 32; 

        printf("PK: ");
        for(int c = 0; c < 32; c++)printf("%x",pMasterKeyToUse[c]);
        printf("\n");

        printf("CC: ");
        for(int c = 0; c < 32; c++)printf("%x",pChainCodeToUse[c]);
        printf("\n");

    } 
    printf("--------------\n");

    std::vector<unsigned char> private_key(crypto_sign_ed25519_SECRETKEYBYTES);
    std::vector<unsigned char> public_key(crypto_sign_ed25519_PUBLICKEYBYTES);
    crypto_sign_ed25519_seed_keypair(public_key.data(), private_key.data(), pMasterKeyToUse);

    printf("Public.%i: ",public_key.size());
    for(int i = 0; i < public_key.size();i++)
        printf("%x",public_key[i]);
    printf("\n");

    printf("Private.%i: ",private_key.size());
    for(int i = 0; i < private_key.size();i++)
        printf("%x",private_key[i]);
    printf("\n");
  
    std::string strWallet = bytesToHex(public_key); 
    std::string ret = b58(strWallet.c_str());
    printf("Wallet58: %s\n",ret.data());

    printf("Done\n"); 
    return 0;  

 }