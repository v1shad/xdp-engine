#ifndef TEXT_UTIL_H
#define TEXT_UTIL_H

#include <string>
#include <string_view>
#include <cstdint>
inline std::string url_decode(const std::string& src) {
    std::string ret;
    ret.reserve(src.length());
    for (size_t i = 0; i < src.length(); ++i) {
        if (src[i] == '%') {
            if (i + 2 < src.length()) {
                char hex1 = src[i+1];
                char hex2 = src[i+2];
                int val = 0;
                bool ok = true;
                if (hex1 >= '0' && hex1 <= '9') val = (hex1 - '0') << 4;
                else if (hex1 >= 'a' && hex1 <= 'f') val = (hex1 - 'a' + 10) << 4;
                else if (hex1 >= 'A' && hex1 <= 'F') val = (hex1 - 'A' + 10) << 4;
                else ok = false;
                if (ok) {
                    if (hex2 >= '0' && hex2 <= '9') val |= (hex2 - '0');
                    else if (hex2 >= 'a' && hex2 <= 'f') val |= (hex2 - 'a' + 10);
                    else if (hex2 >= 'A' && hex2 <= 'F') val |= (hex2 - 'A' + 10);
                    else ok = false;
                }
                if (ok) {
                    ret += static_cast<char>(val);
                    i += 2;
                    continue;
                }
            }
        }
        ret += src[i];
    }
    return ret;
}


inline std::string sanitize_utf8(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    const unsigned char* p = reinterpret_cast<const unsigned char*>(sv.data());
    const unsigned char* end = p + sv.size();
    
    while (p < end) {
        if (out.size() >= 128) break;
        
        unsigned char c = *p;
        int len = 0;
        bool valid = false;
        
        if (c < 0x80) {
            len = 1;
            valid = true;
        } else if ((c & 0xE0) == 0xC0) {
            if (c >= 0xC2) { len = 2; valid = true; } 
        } else if ((c & 0xF0) == 0xE0) {
            len = 3; valid = true;
        } else if ((c & 0xF8) == 0xF0) {
            if (c <= 0xF4) { len = 4; valid = true; }
        }
        
        if (!valid || p + len > end) {
            if (out.size() + 3 > 128) break;
            out += "\xEF\xBF\xBD";
            p++;
            continue;
        }
        
        valid = true;
        for (int i = 1; i < len; ++i) {
            if ((p[i] & 0xC0) != 0x80) {
                valid = false;
                break;
            }
        }
        
        if (valid) {
            uint32_t cp = 0;
            if (len == 1) cp = c;
            else if (len == 2) cp = ((c & 0x1F) << 6) | (p[1] & 0x3F);
            else if (len == 3) cp = ((c & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
            else if (len == 4) cp = ((c & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
            
            if ((len == 2 && cp < 0x80) || 
                (len == 3 && cp < 0x800) || 
                (len == 4 && cp < 0x10000)) {
                valid = false; // overlong
            } else if (cp >= 0xD800 && cp <= 0xDFFF) {
                valid = false; // surrogate
            } else if (cp > 0x10FFFF) {
                valid = false; // out of bounds
            }
        }
        
        if (!valid) {
            if (out.size() + 3 > 128) break;
            out += "\xEF\xBF\xBD";
            // advance by len so the whole invalid sequence is replaced by one FFFD
            p += len;
        } else {
            if (out.size() + len > 128) break;
            if (len == 1) {
                if (c < 0x20 || c == 0x7F) {
                    out += '?';
                } else {
                    out += c;
                }
            } else {
                for (int i = 0; i < len; ++i) out += p[i];
            }
            p += len;
        }
    }
    return out;
}

#endif // TEXT_UTIL_H
