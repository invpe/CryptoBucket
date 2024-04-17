/*
    Pure C++ BTC solo.ckpool.org miner test
    clear&&g++ miner1.cpp ../Core/CJZon.cpp -I ../Core/  -lsodium&&./a.out 
    or endlessly: while true; do ./a.out; done 
*/

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
#include <sodium.h>
#include "../Core/CJZon.h"

#define MAX_TRIES 1000000
std::string strBTCAddress = "xxxxxxxxxxxxxxxxxxxx";

std::string hexStringToBinary(const std::string& hexString) {
    std::string binaryString;
    for (size_t i = 0; i < hexString.size(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        char byte = (char)std::strtol(byteString.c_str(), nullptr, 16);
        binaryString.push_back(byte);
    }
    return binaryString;
}

std::string binaryToHex(const std::string& binaryStr) {
    std::stringstream ss;
    for (unsigned char c : binaryStr) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

std::string double_sha256_to_bin_string(const std::string& input) {
    unsigned char hash1[crypto_hash_sha256_BYTES];
    unsigned char hash2[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash1, reinterpret_cast<const unsigned char*>(input.data()), input.size());
    crypto_hash_sha256(hash2, hash1, crypto_hash_sha256_BYTES);
    return std::string(reinterpret_cast<char*>(hash2), crypto_hash_sha256_BYTES);
}

std::vector<unsigned char> hexStringToByteArray(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string littleEndianToBigEndian(const std::string& input) {
    std::string output = input;
    std::reverse(output.begin(), output.end());
    return output;
}

std::string toHexString(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::string toHexString(const std::string& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::string convert_to_little_endian(const std::string& input) {
    std::string reversed_input;
    for (size_t i = input.size(); i > 0; i -= 2) {
        reversed_input += input.substr(i - 2, 2);
    }
    std::string binary_input = hexStringToBinary(reversed_input);
    return toHexString(binary_input);
}

std::string createPayload(const std::string& address, const std::string& job_id, const std::string& extranonce2,
                          const std::string& ntime, unsigned int nonce) {
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << nonce;
    std::string nonce_hex = ss.str();


    return "{\"params\": [\"" + address + "\", \"" + job_id + "\", \"" + extranonce2 + "\", \"" + ntime +
           "\", \"" + nonce_hex + "\"], \"id\": 1, \"method\": \"mining.submit\"}\n";
}

int connect_to_pool(const char* host, int port) {
    hostent *he;
    if ((he = gethostbyname(host)) == 0) {
        std::cerr << "Cant get hostname]\n";
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = *((in_addr *)he->h_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection Failed\n";
        return -1;
    }
    return sock;
}

void send_data(int sock, const std::string& data) {
    send(sock, data.c_str(), data.size(), 0);
}

std::string receive_data(int sock) {
    char buffer[5024] = {0};
    size_t bytes_read = recv(sock, buffer, sizeof(buffer), 0);
    return std::string(buffer, bytes_read);
}

std::string double_sha256_to_hex_string(const std::string& input) {
    unsigned char hash[crypto_hash_sha256_BYTES];
    unsigned char final_hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, reinterpret_cast<const unsigned char*>(input.data()), input.size());
    crypto_hash_sha256(final_hash, hash, crypto_hash_sha256_BYTES);
    return toHexString(std::vector<unsigned char>(final_hash, final_hash + crypto_hash_sha256_BYTES));
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

std::string reverse_hex(const std::string &hex) {
    std::string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        result = hex.substr(i, 2) + result;
    }
    return result;
}

std::string create_block_header(const std::string& version, const std::string& prevhash,
                                 const std::string& merkle_root, const std::string& nbits,
                                 const std::string& ntime, int nonce) {
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << nonce;
    std::string nonce_hex = ss.str();

    std::string block_header = (version) + (prevhash) + (merkle_root) + (nbits)+ (ntime)+ (nonce_hex) +
                               "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";

    return block_header;
}

std::string calculate_merkle_root(const std::string& coinbase_hash_bin, const std::vector<std::string>& merkle_branch) {
    std::string merkle_root = coinbase_hash_bin;

    for (const std::string& hash : merkle_branch) {
        std::string combined_hash = merkle_root + hexStringToBinary(hash);
        std::string hash_result = double_sha256_to_bin_string(combined_hash);
        merkle_root = hash_result;
    }

    return toHexString(merkle_root);
}

std::string nbitsToTarget(const std::string& nbits) {
    std::string target = nbits.substr(2);
    int exponent = std::stoi(nbits.substr(0, 2), nullptr, 16) - 3;

    for (int i = 0; i < exponent; i++) {
        target += "00";
    }

    while (target.length() < 64) {
        target = "0" + target;
    }

    return target;
}


std::string generate_extranonce2(int size) { 

    uint64_t random_number = rand()%UINT64_MAX;
 
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(size*2)  << std::hex << random_number; // Convert number to hex with padding

    std::string result = ss.str(); 
    return result;
} 

int main() {   
    srand(time(0));
    std::vector<std::string> merkle_branch;
    Jzon::Node rootNode;
    Jzon::Parser _Parser; 


    if (sodium_init() < 0) {
        std::cerr << "libsodium initialization failed" << std::endl;
        return 1;
    }
 
    const char* host = "solo.ckpool.org";
    int port = 3333;

    printf("[MINER] Connecting to the pool\n");
    int sock = connect_to_pool(host, port);
    if (sock == -1) return 1;


    printf("[MINER] Authorizing with the pool\n");
    send_data(sock, "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": []}\n");
    std::string response = receive_data(sock);
    std::vector<std::string> vReturn = split_string(response,'\n');

    printf("[POOL] %s\n", vReturn[0].data());
    rootNode = _Parser.parseString(vReturn[0]);
    //rootNode = _Parser.parseFile("1.json"); 

    if (!rootNode.isValid()) {
        std::cerr << "Error parsing JSON\n";
        return -1;
    }

    Jzon::Node jzResults = rootNode.get("result");
    Jzon::Node A = jzResults.get(0);
    Jzon::Node B = A.get(0);
    Jzon::Node C = B.get(1);
    std::string strSubDetails = C.toString();
    std::string srtExtraNonce1 = jzResults.get(1).toString();   
    int iExtraNonce2_Size = jzResults.get(2).toInt();

    printf("[POOL] %s\n", vReturn[1].data()); 
    rootNode = _Parser.parseString(vReturn[1]);
    if (!rootNode.isValid()) {
        std::cerr << "Error parsing JSON 2\n";
        return -1;
    }

    std::string strPayload = "{\"params\": [\"" + strBTCAddress + "\", \"password\"], \"id\": 2, \"method\": \"mining.authorize\"}\n";
    printf("[MINER] %s\n",strPayload.data());
    send_data(sock,strPayload.c_str());

    response = receive_data(sock); 
    vReturn.clear();
    vReturn = split_string(response,'\n');

    printf("[POOL] %s\n", vReturn[0].data()); 

    //
    rootNode = _Parser.parseString(vReturn[0]);
    //rootNode = _Parser.parseFile("3.json"); 
    if (!rootNode.isValid()) {
        std::cerr << "Error parsing JSON 3\n";
        return -1;
    }

    jzResults = rootNode.get("params");
    std::string job_id = jzResults.get(0).toString();
    std::string prevhash = jzResults.get(1).toString();
    std::string coinb1 = jzResults.get(2).toString();
    std::string coinb2 = jzResults.get(3).toString();

    const Jzon::Node jzMerkeleBranch = jzResults.get(4);   
    for(int a = 0; a < jzMerkeleBranch.getCount(); a++) {
        Jzon::Node _Node = jzMerkeleBranch.get(a); 
        std::string strMerkle =  _Node.toString();
        merkle_branch.push_back(strMerkle);
    }

    std::string version = jzResults.get(5).toString();
    std::string nbits = jzResults.get(6).toString();
    std::string ntime = jzResults.get(7).toString();
    bool clean_jobs = jzResults.get(8).toBool();
    std::string extranonce2 = generate_extranonce2(iExtraNonce2_Size);   
    std::string coinbase = coinb1+srtExtraNonce1+extranonce2+coinb2; 
    std::string coinbase_hash_bin = double_sha256_to_bin_string(hexStringToBinary(coinbase));
    std::string merkle_root = calculate_merkle_root(coinbase_hash_bin, merkle_branch);
    std::string merkle_root_little_endian = convert_to_little_endian(merkle_root);
    std::string targetHex = nbitsToTarget(nbits); 

     
    uint64_t uiEpoch = time(0);     
    uint32_t uiTries = 0;

    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Define the distribution for nonce values
    std::uniform_int_distribution<std::uint32_t> dist(0, std::numeric_limits<std::uint32_t>::max());

    // Generate a random nonce
    std::uint32_t uiNonce = dist(gen); 

    //For Bitcoin mining, the nonce is a 32-bit (4-byte) field in the block header.
    for(; uiNonce < UINT64_MAX; uiNonce++) 
    {  

        std::string blockHeaderHex = create_block_header(version, 
            prevhash, 
            merkle_root_little_endian, 
            nbits, 
            ntime, 
            uiNonce);
        std::string blockHeaderBin = double_sha256_to_bin_string(hexStringToBinary(blockHeaderHex));
         
        if(uiTries==0)
        { 
            printf("Nonce: %u\n",uiNonce);
            printf("Nbits: %s\n", nbits.data());
            printf("Version: %s\n", version.data());
            printf("extranonce2_size: %i\n", iExtraNonce2_Size);
            printf("extranonce2: %s\n", extranonce2.data());
            printf("Previous hash: %s\n", prevhash.data());            
            printf("Target Hex: %s\n", targetHex.data()); 
            printf("coinb1: %s\n",coinb1.data());
            printf("srtExtraNonce1: %s\n",srtExtraNonce1.data()); 
            printf("coinb2: %s\n",coinb2.data());
            printf("coinbase: %s\n",coinbase.data());
            printf("coinbase_hash_bin: %s\n", binaryToHex(coinbase_hash_bin).data());
            printf("merkle_root_little_endian: %s\n", merkle_root_little_endian.data());
            printf("blockHeader: %s\n", blockHeaderHex.data());
            printf("blockheaderhash: %s\n",binaryToHex(blockHeaderBin).data()); 

        }


        if ((binaryToHex(blockHeaderBin)) < targetHex) {
            std::string strReturn =  createPayload(strBTCAddress, job_id, extranonce2, ntime, uiNonce);            
            send_data(sock,strPayload.c_str());
            std::string response = receive_data(sock); 
            printf("[SUCCESS] Found nonce %u\n",uiNonce);
            printf("[POOL] %s\n", response.data()); 
            break;
        }  

        if(time(0) - uiEpoch > 1) { 
            printf("[MINING] %u %u-%u Last block header %s\n",  uiNonce,uiTries,MAX_TRIES, blockHeaderHex.data());
            uiEpoch = time(0);
        }

        //
        if(uiTries>MAX_TRIES)
            break;

        uiTries++; 
    } 
    close(sock);

    printf("[MINING] Stopped, all iterations complete\n");
    return 0;
} 
