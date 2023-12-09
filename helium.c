/*
* 12 words mnemonic to helium (legacy) address (c) invpe 2k23
* https://github.com/invpe/HeliumSolana
* g++ helium.c -lsodium
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <sstream>
#include <string>
#include <algorithm>
#include <bitset>
#include <sodium.h>
#include <openssl/sha.h>   

const int MAINNET = 0x00;
const int ED25519_KEY_TYPE = 0x01; 
 
std::vector<std::string> wordlist;

static const char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char reverse_table[128] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
}; 
// https://gist.github.com/miguelmota/ff591873da4f76393ce48efe62d49fd1#gistcomment-3321715 
inline static constexpr const uint8_t base58map[] = {
    '1', '2', '3', '4', '5', '6', '7', '8',
    '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
    'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z' };
std::string EncodeBase58(const std::vector<uint8_t>& data, const uint8_t* mapping)
{
    std::vector<uint8_t> digits((data.size() * 138 / 100) + 1);
    size_t digitslen = 1;
    for (size_t i = 0; i < data.size(); i++)
    {
        uint32_t carry = static_cast<uint32_t>(data[i]);
        for (size_t j = 0; j < digitslen; j++)
        {
            carry = carry + static_cast<uint32_t>(digits[j] << 8);
            digits[j] = static_cast<uint8_t>(carry % 58);
            carry /= 58;
        }
        for (; carry; carry /= 58)
            digits[digitslen++] = static_cast<uint8_t>(carry % 58);
    }
    std::string result;
    for (size_t i = 0; i < (data.size() - 1) && !data[i]; i++)
        result.push_back(mapping[0]);
    for (size_t i = 0; i < digitslen; i++)
        result.push_back(mapping[digits[digitslen - 1 - i]]);
    return result;
}

uint8_t binary_to_byte(const std::string& binary) { 
    if (binary.size() != 8) {
        throw std::invalid_argument("Binary string must be 8 characters long.");
    }
    uint8_t result = 0;
    for (char bit : binary) {
        result = (result << 1) | (bit - '0');
    } 
    return result;
}   
std::string derive_checksum_bits(const std::vector<uint8_t>& entropy_bytes) {
    // Calculate checksum length based on entropy length
    size_t checksum_length = entropy_bytes.size() / 4;

    // Calculate the SHA-256 hash of 'entropy_bytes'
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    crypto_hash_sha256(sha256_hash, entropy_bytes.data(), entropy_bytes.size());

    // Convert the hash to a binary string
    std::string binary_hash;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        binary_hash += std::bitset<8>(sha256_hash[i]).to_string();
    }

    // Extract the checksum bits
    std::string checksum_bits = binary_hash.substr(0, checksum_length);

    return checksum_bits;
}
std::vector<uint8_t> mnemonic_to_entropy(const std::vector<std::string>& mnemonic) {

    std::string bits;
    for (const std::string& word : mnemonic) {
        auto it = std::find(wordlist.begin(), wordlist.end(), word);
        if (it == wordlist.end()) {
            throw std::runtime_error("Seed word not found in wordlist.");
        }
        size_t idx = std::distance(wordlist.begin(), it); 
        bits += std::bitset<11>(idx).to_string();
    }

    size_t divider_index = bits.size() - bits.size() / 33;    
    std::string entropy_bits = bits.substr(0, divider_index); 

    std::vector<uint8_t> entropy_bytes;

    for (size_t i = 0; i < entropy_bits.size(); i += 8) {
        std::string strtemp = entropy_bits.substr(i, 8);
        entropy_bytes.push_back(binary_to_byte(strtemp));
    } 
    std::string checksum_bits = bits.substr(divider_index);
    std::string derived_checksum = derive_checksum_bits(entropy_bytes);

    if (checksum_bits != "0000" && derived_checksum != checksum_bits) {
        throw std::runtime_error("Invalid checksum");
    } 

    return entropy_bytes;
} 
//https://github.com/helium/enacl/blob/efb74b1af1df7f46f6ade488f16ec365af3ce47f/c_src/sign.c#L362
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeyPairFromEntropy(const std::vector<uint8_t>& seed) {
    if (seed.size() != crypto_sign_SEEDBYTES) {
        throw std::runtime_error("Invalid entropy size, must be 32 bytes");
    }

    std::vector<uint8_t> privateKey(crypto_sign_SECRETKEYBYTES);
    std::vector<uint8_t> publicKey(crypto_sign_PUBLICKEYBYTES);

    if (crypto_sign_seed_keypair(publicKey.data(), privateKey.data(), seed.data()) != 0) {
        throw std::runtime_error("Error generating key pair");
    }

    return std::make_pair(privateKey, publicKey);
}
std::vector<uint8_t> doubleSha256Libsodium(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(crypto_hash_sha256_BYTES);
    // First SHA-256 hash
    crypto_hash_sha256(hash.data(), data.data(), data.size());
    // Second SHA-256 hash on the result of the first hash
    crypto_hash_sha256(hash.data(), hash.data(), crypto_hash_sha256_BYTES);

    return hash;
}   
std::string bs58CheckEncode(int version, const std::vector<uint8_t>& binary) {
    std::vector<uint8_t> vPayload = {static_cast<uint8_t>(version)};
    vPayload.insert(vPayload.end(), binary.begin(), binary.end());

    std::vector<uint8_t> checksum = doubleSha256Libsodium(vPayload);
    checksum.resize(4); // Only the first 4 bytes of the checksum are used.
    vPayload.insert(vPayload.end(), checksum.begin(), checksum.end());
  
    std::string encodedData   = EncodeBase58(vPayload, base58map); 
    return encodedData;

}
std::string constructHeliumAddress(int version, int netType, int keyType, const std::vector<uint8_t>& publicKey) {  
    std::vector<uint8_t> bin = {static_cast<uint8_t>(netType | keyType)};
    bin.insert(bin.end(), publicKey.begin(), publicKey.end());
    return bs58CheckEncode(version,bin);
}  
int main(int argc, char* argv[]) {  

    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
 
    // Load all mnemonics
    std::ifstream file("mnemonics.txt");  // Open the file
    if (!file) {
        std::cerr << "Failed to open mnemonics.txt" << std::endl;
        return 1;
    }

    // Load mnemonic words 
    std::string word;
    int counter = 0;
    while (std::getline(file, word)) {
        wordlist.push_back(word);         
    }
    file.close(); 

    // Load mnemonic words from command-line argument
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " \"mnemonic phrase\"" << std::endl;
        return 1;
    }
 
    std::string mnemonicPhrase = argv[1];
    std::istringstream iss(mnemonicPhrase);
    std::vector<std::string> seedWords((std::istream_iterator<std::string>(iss)), std::istream_iterator<std::string>());

    std::vector<uint8_t> entropy = mnemonic_to_entropy(seedWords);    
    std::cout << "Entropy size: " << entropy.size() << std::endl;

    if (entropy.size() != 32) {
        std::cout << "Entropy < 32, duplicating." << std::endl; 
        entropy.insert(entropy.end(), entropy.begin(), entropy.end());
    }

    std::cout << "Entropy size: " << entropy.size() << std::endl;
 
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> keyPair = generateKeyPairFromEntropy( entropy ); 
  
    std::cout << "Private Key size: " << keyPair.first.size() << std::endl;
    std::cout << "Public Key size: " << keyPair.second.size() << std::endl;

    std::vector<uint8_t> publicKey = keyPair.second;

    std::string heliumAddress = constructHeliumAddress(0, MAINNET, ED25519_KEY_TYPE, publicKey);
    std::cout << "Address: " << heliumAddress << std::endl;
  
    return 0;
}
