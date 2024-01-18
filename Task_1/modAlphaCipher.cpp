#include "modAlphaCipher.h"

modAlphaCipher::modAlphaCipher(const std::string& skey)
{
    for(unsigned i = 0; i < numAlpha.size(); i++)
        alphaNum[numAlpha[i]] = i;
    key = convert(getValidKey(skey));
}

std::string modAlphaCipher::encrypt(const std::string& open_text)
{
    std::vector <int> work = convert(getValidOpenText(open_text));
    for(unsigned i = 0; i < work.size(); i++)
        work[i] = (work[i] + key[i % key.size()]) % alphaNum.size();
    return convert(work);
}

std::string modAlphaCipher::decrypt(const std::string& cipher_text)
{
    std::vector <int> work = convert(getValidCipherText(cipher_text));
    for(unsigned i = 0; i < work.size(); i++)
        work[i] = (work[i] + alphaNum.size() - key[i % key.size()]) % alphaNum.size();
    return convert(work);
}

inline std::vector <int> modAlphaCipher::convert(const std::string& s)
{
    std::vector <int> result;
    std::wstring ws = codec.from_bytes(s); // перекодируем из UTF-8 в UTF32
    for(auto c : ws){
        result.push_back(alphaNum[c]);
    }
    return result;
}

inline std::string modAlphaCipher::convert(const std::vector<int>& v)
{
    std::wstring ws;
    for(auto i : v) {
        ws.push_back(numAlpha[i]);
    }
    std::string result = codec.to_bytes(ws);
    return result;
}

inline std::string modAlphaCipher::getValidKey(const std::string& s)
{
    std::string result;
    std::wstring ws = codec.from_bytes(s);
    if(ws.empty())
        throw cipher_error("Empty key");
    
    std::wstring tmp(ws);
    for(auto& c : tmp) {
        if(!isalpha(c, loc))
            throw cipher_error(std::string("Invalid key ") + s);
        if(islower(c, loc))
            c = toupper(c, loc);
    }
    result = codec.to_bytes(tmp);
    return result;
}

inline std::string modAlphaCipher::getValidOpenText(const std::string& s)
{
    std::string result;
    std::wstring tmp;
    std::wstring ws = codec.from_bytes(s);
    for(auto c : ws) {
        if(isalpha(c, loc)) {
            if(islower(c, loc))
                tmp.push_back(toupper(c, loc));
            else tmp.push_back(c);
        }
    }
    if(tmp.empty())
        throw cipher_error("Empty open text");
    result = codec.to_bytes(tmp);
    return result;
}

inline std::string modAlphaCipher::getValidCipherText(const std::string& s)
{
    std::string result;
    std::wstring ws = codec.from_bytes(s);
    if(ws.empty())
        throw cipher_error("Empty cipher text");
    for(auto c : ws) {
        if(!isupper(c, loc))
            throw cipher_error(std::string("Invalid cipher text ") + s);
    }
    result = codec.to_bytes(ws);
    return result;
}



