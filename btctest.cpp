/*


*/
#include <assert.h>
#include <random>
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <sodium.h>
#include "../Core/CJZon.h"

#define SHA256M_BLOCK_SIZE 32 
static const uint32_t EXPONENT_SHIFT = 24;
static const uint32_t MANTISSA_MASK = 0xffffff;

std::string strBTCAddress = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; 
 
#pragma pack(push, 1) // Set alignment to 1 byte
struct Block
{
    uint32_t    version;           // Block version
    uint8_t     previous_block[32]={}; // Previous block hash
    uint8_t     merkle_root[32]={};    // Merkle root hash
    uint32_t    ntime;             // Timestamp
    uint32_t    nbits;             // Target difficulty
    uint32_t    nonce;             // Nonce 

};
#pragma pack(pop) // Reset alignment to default

uint32_t toLittleEndian(uint32_t value) {
    return ((value & 0xFF) << 24) |
           ((value & 0xFF00) << 8) |
           ((value & 0xFF0000) >> 8) |
           ((value & 0xFF000000) >> 24);
}

 static void reverseBytes(uint8_t *data, size_t len)
{
    size_t half_len = len / 2;
    for (size_t i = 0; i < half_len; ++i)
    {
        uint8_t temp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}
uint8_t hex(char ch)
{
    uint8_t r = (ch > 57) ? (ch - 55) : (ch - 48);
    return r & 0x0F;
} 
void hexStringToByteArray(const char *hexString, uint8_t *output)
{ 
    while (*hexString)
    {
        *output = (hex(*hexString++) << 4) | hex(*hexString++);
        output++;
    }
}

std::string byteArrayToHexString(const uint8_t *byteArray, size_t length)
{
    static const char hex_array[] = "0123456789abcdef";
    std::string result;

    for (size_t i = 0; i < length; i++)
    {
        uint8_t value = byteArray[i];
        result += hex_array[value >> 4];
        result += hex_array[value & 0xF];
    }

    return result;
}
 
/**
 * Reverses the order of bytes in the given data array and flips each byte.
 *
 * @param data The data array to be reversed and flipped.
 * @param len The length of the data array.
 */
static void reverseBytesAndFlip(uint8_t *data, size_t len)
{
    for (unsigned int i = 0; i < len / 4; ++i)
    {
        uint8_t temp[4];
        for (int j = 0; j < 4; ++j)
        {
            temp[j] = data[i * 4 + j];
        }
        for (int j = 0; j < 4; ++j)
        {
            data[i * 4 + j] = temp[3 - j];
        }
    }
} 
/**
 * Compares two byte arrays in little-endian order.
 *
 * @param a The first byte array to compare.
 * @param b The second byte array to compare.
 * @param byte_len The length of the byte arrays.
 * @return -1 if a is less than b, 1 if a is greater than b, 0 if they are equal.
 */static int littleEndianCompare(const unsigned char *a, const unsigned char *b, size_t byte_len)
{
    for (size_t i = byte_len - 1; ; --i)
    {
        if (a[i] < b[i])
            return -1;
        else if (a[i] > b[i])
            return 1;
         if (i == 0) 
            break;      
    }
    return 0;
} 
void sha256_double(const void *data, size_t len, uint8_t output[32]) {
    uint8_t intermediate_hash[32];

    // First SHA-256 hash
    crypto_hash_sha256(intermediate_hash, (const unsigned char *)data, len);

    // Second SHA-256 hash
    crypto_hash_sha256(output, intermediate_hash, sizeof(intermediate_hash));
}
 
std::vector<std::string> split_string(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0;
    size_t end = str.find(delimiter);

    while (end != std::string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + 1;
        end = str.find(delimiter, start);
    }

    tokens.push_back(str.substr(start, end - start));
    return tokens;
}
 
void generateCoinbaseHash(const std::string &coinbase, std::string &coinbase_hash)
{    
    const size_t len = coinbase.length();
    uint8_t coinbaseBytes[len / 2];
    hexStringToByteArray(coinbase.c_str(), coinbaseBytes);
    uint8_t hash[SHA256M_BLOCK_SIZE];
    sha256_double(coinbaseBytes, len / 2, hash);
    coinbase_hash = byteArrayToHexString(hash, SHA256M_BLOCK_SIZE); 
}
void calculateMerkleRoot(const std::string &coinbase_hash, const std::vector<std::string> &merkle_branch, std::string &merkle_root)
{
    uint8_t hash[SHA256M_BLOCK_SIZE] = {};
    hexStringToByteArray(coinbase_hash.c_str(), hash);      
    for (const auto &branch : merkle_branch)
    {

        uint8_t merkle_branch_bin[32];
        hexStringToByteArray(branch.c_str(), merkle_branch_bin);

        uint8_t merkle_concatenated[SHA256M_BLOCK_SIZE * 2];
        for (size_t j = 0; j < 32; j++)
        {
            merkle_concatenated[j] = hash[j];
            merkle_concatenated[32 + j] = merkle_branch_bin[j];
        }
 
        sha256_double(merkle_concatenated, sizeof(merkle_concatenated), hash);
    }

    merkle_root = byteArrayToHexString(hash, SHA256M_BLOCK_SIZE);
}

// Adjust the function to accept a reference to a std::mt19937 generator
std::string generate_extra_nonce2(int extranonce2_size, std::mt19937& gen) {
    // Use a uniform distribution to generate random numbers between 0 and UINT32_MAX
    std::uniform_int_distribution<uint32_t> dist(0, std::numeric_limits<uint32_t>::max());

    // Create a stringstream for hexadecimal conversion
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    // Calculate the number of hex digits needed (2 digits per byte)
    int num_hex_digits = 2 * extranonce2_size;

    // Depending on the size requested, generate the appropriate number of random values
    for (int i = 0; i < extranonce2_size / 4; ++i) {
        uint32_t randomValue = dist(gen);
        // Convert the random number to a hex string with padding if necessary
        ss << std::setw(8) << randomValue;  // Each uint32_t gives 8 hex digits
    }

    // Ensure the string is not longer than required (in case of overflow)
    std::string result = ss.str();
    if (result.length() > num_hex_digits) {
        result = result.substr(result.length() - num_hex_digits);
    }

    // Return the formatted string
    return result;
}

 
void nbitsToTarget(const std::string& nbits, uint8_t target[32]) {
    memset(target, 0, 32);  // Initialize the target array to zeros

    // Convert the nbits string to a 32-bit integer.
    char *endPtr;
    uint32_t bits_value = strtoul(nbits.c_str(), &endPtr, 16);

    // Check for conversion errors
    if (*endPtr != '\0' || bits_value == 0) {
        std::cerr << "Error: Invalid nbits value" << std::endl;
        exit(EXIT_FAILURE); // Use standard exit code for failure
    }

    // Extract the exponent and mantissa from bits_value
    uint32_t exp = bits_value >> EXPONENT_SHIFT;
    uint32_t mant = bits_value & MANTISSA_MASK;

    // Calculate the bit shift value
    uint32_t bitShift = 8 * (exp - 3);

    // Calculate the byte index in a 32-byte array
    int byteIndex = 29 - (bitShift / 8); // Calculate start position in the array

    if (byteIndex < 0) {
        std::cerr << "Error: Invalid index, nBits exponent too small" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Convert mantissa into target at the calculated byte index
    target[byteIndex] = (mant >> 16) & 0xFF;        // Most significant byte
    target[byteIndex + 1] = (mant >> 8) & 0xFF;
    target[byteIndex + 2] = mant & 0xFF;            // Least significant byte


}
static void hexInverse(unsigned char *hex, size_t len, char *output)
{
    for (size_t i = len - 1; i < len; --i)
    {
        sprintf(output, "%02x", hex[i]);
        output += 2;
    }
}

/**
 * Converts a string to little-endian byte representation.
 *
 * @param in The input string to convert.
 * @param output The output buffer to store the converted bytes.
 */
void stringToLittleEndianBytes(const char *in, uint8_t *output)
{
    size_t len = strlen(in);
    assert(len % 2 == 0);

    for (size_t s = 0, b = (len / 2 - 1); s < len; s += 2, --b)
    {
        output[b] = (unsigned char)(hex(in[s]) << 4) + hex(in[s + 1]);
    }
}
void print_hex(const uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::endl;
} 
std::string convert_to_little_endian(const std::string& input) {
    std::string reversed_input;
    for (size_t i = input.size(); i > 0; i -= 2) {
        reversed_input += input.substr(i - 2, 2);
    } 
    return reversed_input;
} 
 
// Function to convert a value to little-endian hexadecimal representation
std::string littleEndian(uint32_t value) {
    std::ostringstream oss;
    // Use std::hex to format as hexadecimal
    oss << std::hex << std::setw(8) << std::setfill('0') << value;
    // Convert to little-endian by reversing byte order
    std::string hexStr = oss.str();
    std::string result;
    for (int i = hexStr.size() - 2; i >= 0; i -= 2) {
        result += hexStr.substr(i, 2);
    }
    return result;
}
// Function to convert an integer to little-endian byte representation
std::string integerToLittleEndian(uint32_t value) {
    std::string result;
    for (int i = 0; i < sizeof(value); ++i) {
        result += static_cast<char>((value >> (i * 8)) & 0xFF);
    }
    return result;
} 
void reverse_bytes(uint8_t * data, size_t len) {
    for (int i = 0; i < len / 2; ++i) {
        uint8_t temp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}  
void serializeBlockHeader(const Block& block, std::vector<uint8_t>& buffer) {
    buffer.clear();

    // Version: little endian
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&block.version), reinterpret_cast<const uint8_t*>(&block.version) + sizeof(block.version));

    // Previous Block Hash: little endian, assuming it's provided correctly
    buffer.insert(buffer.end(), block.previous_block, block.previous_block + 32);

    // Merkle Root:
    // The output of the SHA-256 hash function, such as the hash of the Merkle root, is typically represented in big endian format by convention. 
    // We have to reverse the hash
    std::vector<uint8_t> merkleRoot(block.merkle_root, block.merkle_root + 32);
    std::reverse(merkleRoot.begin(), merkleRoot.end());
    buffer.insert(buffer.end(), merkleRoot.begin(), merkleRoot.end());

    // Time: little endian
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&block.ntime), reinterpret_cast<const uint8_t*>(&block.ntime) + sizeof(block.ntime));

    // Bits: little endian
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&block.nbits), reinterpret_cast<const uint8_t*>(&block.nbits) + sizeof(block.nbits));

    // Nonce: little endian
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&block.nonce), reinterpret_cast<const uint8_t*>(&block.nonce) + sizeof(block.nonce));
}
 

int main(int argc, char*argv[]) {   
    
    srand(time(0));    
    Jzon::Node rootNode;
    Jzon::Parser _Parser; 

    // Subscribe
    std::string id;
    std::string extranonce1;
    int extranonce2_size;

    // Notification
    std::string job_id;
    std::string prevhash;
    std::string coinb1;
    std::string coinb2;
    std::vector<std::string> merkle_branch;
    std::string version;
    std::string nbits;
    std::string ntime;
    bool clean_jobs;

    std::string extranonce2;
        
    if(argc<3)
    {
        printf("./start subscribe.json notify.json\n");
        exit(0);
    }

    printf("SUBSCRIBE: %s\n",argv[1]);
    printf("NOTIFY: %s\n", argv[2]);

    if (sodium_init() < 0) {
        std::cerr << "libsodium initialization failed" << std::endl;
        return 1;
    } 
 
    rootNode = _Parser.parseFile(argv[1]); 
    if (!rootNode.isValid()) {
        std::cerr << "Error parsing JSON\n";
        return -1;
    }

    Jzon::Node jzResults = rootNode.get("result");
    Jzon::Node A = jzResults.get(0);
    Jzon::Node B = A.get(0);
    Jzon::Node C = B.get(1);
    id = C.toString();
    extranonce1 = jzResults.get(1).toString();   
    extranonce2_size = jzResults.get(2).toInt(); 

    rootNode = _Parser.parseFile(argv[2]); 
    if (!rootNode.isValid()) {
        std::cerr << "Error parsing JSON 3\n";
        return -1;
    }
 

    jzResults   = rootNode.get("params");
    job_id  = jzResults.get(0).toString();
    prevhash = jzResults.get(1).toString();  
    coinb1  = jzResults.get(2).toString();   
    coinb2  = jzResults.get(3).toString();  
    version = jzResults.get(5).toString(); 
    nbits   = jzResults.get(6).toString();     
    ntime   = jzResults.get(7).toString(); 
    clean_jobs  = jzResults.get(8).toInt();       
    const Jzon::Node jzMerkeleBranch = jzResults.get(4);   
    for(int a = 0; a < jzMerkeleBranch.getCount(); a++) {
        Jzon::Node _Node = jzMerkeleBranch.get(a); 
        std::string strMerkle =  _Node.toString(); 
        merkle_branch.push_back(strMerkle);        
    }

    ///////////////////////////
    // Done with parsing     //
    ///////////////////////////
    uint64_t uiTick = 0;    

    // Prepare a random machine
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::uint32_t> dist(0, std::numeric_limits<std::uint32_t>::max());

    // Calculate target this never changes    
    uint8_t target[32];
    nbitsToTarget(nbits,target);
    // Reverse it
    reverseBytes(target,32);

    // Endless approach, mutating nonce and extranonce2
    while(1)
    {                
        Block block;
        extranonce2 = generate_extra_nonce2(extranonce2_size,gen);   

        // Prev hash ready to use from ckpool (already reversed)
        hexStringToByteArray(prevhash.c_str(), block.previous_block);                            

        // Calculate coinbase
        const std::string coinbase = coinb1 + extranonce1 + extranonce2 + coinb2;    
        std::string coinbase_hash;
        generateCoinbaseHash(coinbase, coinbase_hash);
        
        // Calculate merkle - this will be reversed
        //The output of the SHA-256 hash function, such as the hash of the Merkle root, is typically represented in big endian format by convention. 
        std::string merkle_root;
        calculateMerkleRoot(coinbase_hash, merkle_branch, merkle_root);
        hexStringToByteArray(merkle_root.c_str(), block.merkle_root);
        
        // Update block header
        // https://bitcoin.stackexchange.com/questions/59614/mining-block-header-bit-reversing/59615#59615
        block.version   = strtoul(version.c_str(), nullptr, 16); // dont reverse, already rev by pool
        block.ntime     = strtoul(ntime.c_str(), nullptr, 16);   // dont reverse, already rev by pool

        block.nbits             = strtoul(nbits.c_str(), nullptr, 16);   // dont reverse, already rev by pool 
        block.nonce             = dist(gen);          

        // Altering ntime is an option
        // Example: Maximum allowed future time difference (Bitcoin network's rule)
        std::uniform_int_distribution<std::uint32_t> distTime(0, 7200);        
        block.ntime += distTime(gen);                    

        // Finaly build the block header and reverse things as the should
        std::vector<uint8_t> vHeader;
        serializeBlockHeader(block,vHeader);

        // Hash it
        uint8_t block_hash[32];    
        sha256_double(vHeader.data(), vHeader.size(), block_hash); 

        // Reverse as output of SHA256 is always BIG endian, but our target is LE
        // The output of the SHA-256 hash function, such as the hash of the Merkle root, is typically represented in big endian format by convention. 
        reverseBytes(block_hash,32);


        if(time(0) - uiTick>5)
        {
            printf("Coinbase1           : %s\n", coinb1.data());
            printf("Coinbase2           : %s\n", coinb2.data());
            printf("Extranonce1         : %s\n", extranonce1.data());
            printf("Extranonce2         : %s\n", extranonce2.data());
            printf("Extranonce2 size    : %i\n", extranonce2_size); 

            for(int z =0; z<merkle_branch.size(); z++)
            {
                std::cout << "Merkle "<<z<<"            :"<< merkle_branch[z]<<std::endl;
            }

            printf("Version             : %u / %s\n", block.version,version.data());                        
            printf("Merklehash          : %s\n", merkle_root.data());
            printf("ntime               : %02x / %s\n", block.ntime,ntime.data());
            printf("nbits               : %02x / %s\n", block.nbits,nbits.data());
            printf("Nonce               : %02x\n", block.nonce);                                    
            printf("Block prevhash      : ");
            for(int x = 0; x < 32; x++)printf("%02x", block.previous_block[x]);printf("\n");
            printf("Block Header        : ");for(int iC = 0; iC < vHeader.size(); iC++) printf("%02x", vHeader[iC]);printf("\n");
            printf("Block hash(reversed): ");for(int iC = 0; iC < sizeof(block_hash);iC++){printf("%02x",block_hash[iC]);}printf("\n");            
            printf("Target(reversed)    : ");for(int iC = 0; iC < sizeof(target);iC++){printf("%02x",target[iC]);}printf("\n");

            uiTick = time(0);
        }  

/*         
     uint8_t winnig_block_hash[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8 bytes
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 16 bytes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 24 bytes (0x0F)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // 32 bytes
    };  
*/

        if(littleEndianCompare(block_hash,target,32)<0)
        {
            printf("YESSSSSSSSSSSSSSSSSSSSSSSSSSSSSS %u %s\n",block.nonce,extranonce1.data());
            exit(0);
        }    
    }  
    printf("[MINING] Stopped, all iterations complete\n");
    return 0;

}  
