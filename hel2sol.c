// messy Convert Helium Public Key (wallet id) to Solana Wallet
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


const std::string BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base58_encode(const std::vector<unsigned char>& input) {
  // Convert the input to a big number.
  BIGNUM* bn = BN_bin2bn(input.data(), input.size(), nullptr);
  
  // Allocate a buffer to hold the base-58 encoded output.
  size_t len = (size_t)BN_num_bits(bn) / 6 + 1;
  std::vector<unsigned char> buf(len);
  
  // Convert the big number to base-58.
  for (int i = 0; i < len; i++) {
    BN_div_word(bn, 58);
    buf[len - i - 1] = BASE58_ALPHABET[BN_mod_word(bn, 58)];
  }
  
  // Add leading zeros for each input zero byte.
  int zeros = 0;
  for (unsigned char b : input) {
    if (b != 0) break;
    zeros++;
  }
  buf.insert(buf.begin(), zeros, '1');
  
  // Free the big number.
  BN_free(bn);
  
  // Convert the output buffer to a string.
  return std::string(buf.begin(), buf.end());
}  
std::vector<unsigned char> base58_decode(const std::string& input)
{
    static const char* BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    std::vector<unsigned char> result(input.size() * 733 / 1000 + 1, 0);
    for (const char c : input) {
        auto value = strchr(BASE58_CHARS, c) - BASE58_CHARS;
        if (value < 0) {
            throw std::invalid_argument("Invalid Base58 character");
        }
        for (int j = result.size() - 1; j >= 0; j--) {
            value += 58 * result[j];
            result[j] = value % 256;
            value /= 256;
        }
    }
    int i = 0;
    while (i < result.size() && result[i] == 0) {
        i++;
    }
    std::vector<unsigned char> output(result.size() - i, 0);
    for (int j = 0; j < output.size(); j++) {
        output[j] = result[i + j];
    }
    return output;
}



int main(int argc, char*argv[]) 
{
     
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
 	
 
    // Convert Helium Pub_key (wallet id) to Solana
    // https://docs.helium.com/solana/migration/exchange/ 
    std::string strHeliumWallet = std::string(argv[1]);  
    std::vector<unsigned char> vFromBase = base58_decode(strHeliumWallet);  
    std::vector<unsigned char> vPublicKey(vFromBase.begin() + 1, vFromBase.end()-4); 
    std::string strSolanaWalletFromHelium = base58_encode(vPublicKey); 

    printf("Helium: %s\n",strHeliumWallet.data());
    printf("Solana: %s\n",strSolanaWalletFromHelium.data());

    return 0;  

}