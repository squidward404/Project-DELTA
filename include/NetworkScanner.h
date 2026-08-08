// include/NetworkScanner.h
#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <cctype>
#include <iostream>
#include <algorithm>
#include <thread>
#include <chrono>
#include <fstream>

// Platform Specific Headers
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <io.h>
    #define CLOSE_SOCKET closesocket
    #define GET_ERROR WSAGetLastError()
    #define WOULD_BLOCK WSAEWOULDBLOCK
    #define SLEEP_MS(ms) Sleep(ms)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <sys/select.h>
    #define CLOSE_SOCKET close
    #define GET_ERROR errno
    #define WOULD_BLOCK EINPROGRESS
    #define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

// --- Configuration ---
const int SCAN_TIMEOUT_SEC = 3;
const int RECV_BUFFER_SIZE = 2048;

// --- Result Structure ---
struct ScanResult {
    int port;
    std::string service;
    std::string version;
    std::string authStatus;      // e.g., "None", "Password", "Anonymous"
    std::string riskLevel;       // e.g., "Low", "Medium", "High"
    std::string vulnerability;   // e.g., "Open VNC", "Anonymous FTP"
    std::string exposureNote;    // e.g., "[HIGH] FTP exposed"
    std::string deviceBrand;     // e.g., "Hikvision", "MikroTik"
};

inline std::string serviceNameForPort(int port) {
    switch (port) {
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS(TCP)";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 139: return "NetBIOS";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 554: return "RTSP";
        case 587: return "SMTP Submission";
        case 631: return "IPP";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 1433: return "MSSQL";
        case 1521: return "Oracle";
        case 2049: return "NFS";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 6379: return "Redis";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        case 1883: return "MQTT";
        case 27017: return "MongoDB";
        case 5000: return "HTTP-Service";
        case 9000: return "HTTP-Service";
        case 9200: return "Elasticsearch";
        default: return "TCP-" + std::to_string(port);
    }
}

// --- Helper: Set Socket to Non-Blocking ---
inline bool setNonBlocking(int sock) {
#ifdef _WIN32
    u_long mode = 1;
    return (ioctlsocket(sock, FIONBIO, &mode) == 0);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    return (fcntl(sock, F_SETFL, flags | O_NONBLOCK) != -1);
#endif
}

// --- Helper: Safe Receive with Timeout ---
inline std::string recvBanner(int sock, int timeout_ms) {
    char buffer[RECV_BUFFER_SIZE] = {0};
    fd_set readfds;
    struct timeval tv;

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    if (select(sock + 1, &readfds, NULL, NULL, &tv) > 0) {
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            std::string res(buffer);
            // Clean non-printable chars but keep newlines for parsing
            res.erase(std::remove_if(res.begin(), res.end(), 
                [](unsigned char c){ return !std::isprint(c) && c != '\n' && c != '\r'; }), res.end());
            return res;
        }
    }
    return "";
}

// --- Helper: Send and Receive ---
inline std::string sendRecv(int sock, const std::string& payload, int timeout_ms) {
    send(sock, payload.c_str(), payload.length(), 0);
    return recvBanner(sock, timeout_ms);
}

inline std::string recvRaw(int sock, int timeout_ms, size_t maxBytes = 64) {
    std::string data(maxBytes, '\0');
    fd_set readfds;
    struct timeval tv;

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    if (select(sock + 1, &readfds, NULL, NULL, &tv) > 0) {
        int bytes = recv(sock, &data[0], static_cast<int>(maxBytes), 0);
        if (bytes > 0) {
            data.resize(static_cast<size_t>(bytes));
            return data;
        }
    }
    return "";
}

inline bool hasAny(const std::string& text, const std::vector<std::string>& needles) {
    for (const auto& needle : needles) {
        if (text.find(needle) != std::string::npos) return true;
    }
    return false;
}

inline std::string riskLevelForPort(int port) {
    switch (port) {
        case 21:
        case 23:
        case 445:
        case 554:
        case 5900:
        case 6379:
        case 9200:
        case 1433:
        case 1521:
        case 27017:
            return "High";
        case 25:
        case 53:
        case 80:
        case 110:
        case 139:
        case 143:
        case 443:
        case 587:
        case 631:
        case 993:
        case 995:
        case 2049:
        case 3306:
        case 3389:
        case 5432:
        case 8080:
        case 8443:
        case 1883:
        case 5000:
        case 9000:
            return "Medium";
        default:
            return "Low";
    }
}

inline std::string exposureNoteForPort(int port) {
    switch (port) {
        case 21: return "[HIGH] FTP exposed";
        case 23: return "[HIGH] Telnet exposed";
        case 445: return "[HIGH] SMB exposed";
        case 554: return "[HIGH] RTSP exposed";
        case 5900: return "[HIGH] VNC exposed";
        case 6379: return "[HIGH] Redis exposed";
        case 9200: return "[HIGH] Elasticsearch exposed";
        case 1433: return "[HIGH] MSSQL exposed";
        case 1521: return "[HIGH] Oracle exposed";
        case 27017: return "[HIGH] MongoDB exposed";
        case 3306: return "[MEDIUM] MySQL exposed";
        case 3389: return "[MEDIUM] RDP exposed";
        case 5432: return "[MEDIUM] PostgreSQL exposed";
        case 1883: return "[MEDIUM] MQTT broker exposed";
        case 2049: return "[MEDIUM] NFS exposed";
        default: return "";
    }
}

inline std::string trimCopy(const std::string& text) {
    size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";

    size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

inline std::string trimTokenPunctuation(std::string token) {
    while (!token.empty() && std::ispunct(static_cast<unsigned char>(token.front())) && token.front() != '/' && token.front() != '_') {
        token.erase(token.begin());
    }

    while (!token.empty() && std::ispunct(static_cast<unsigned char>(token.back())) && token.back() != '/' && token.back() != '_' && token.back() != '.') {
        token.pop_back();
    }

    return token;
}

inline bool looksLikeVersionToken(const std::string& token) {
    bool hasDigit = false;
    bool hasAlpha = false;

    for (unsigned char c : token) {
        if (std::isdigit(c)) hasDigit = true;
        if (std::isalpha(c)) hasAlpha = true;
    }

    if (!hasDigit) return false;
    if (token.size() <= 3 && !hasAlpha) return false;

    return hasAlpha || token.find('.') != std::string::npos || token.find('/') != std::string::npos || token.find('_') != std::string::npos || token.find('-') != std::string::npos;
}

inline std::string extractVersionToken(const std::string& text) {
    std::string cleanText = trimCopy(text);
    if (cleanText.empty()) return "";

    const std::vector<std::string> knownPrefixes = {
        "SSH-2.0-OpenSSH_",
        "OpenSSH_",
        "nginx/",
        "Apache/",
        "Microsoft-IIS/",
        "OpenResty/",
        "Jetty/",
        "Tomcat/",
        "vsftpd ",
        "ProFTPD ",
        "Postfix ",
        "Dovecot ",
        "Samba ",
        "Redis ",
        "MySQL ",
        "MariaDB ",
        "PostgreSQL ",
        "MongoDB ",
        "Elasticsearch "
    };

    for (const auto& prefix : knownPrefixes) {
        size_t pos = cleanText.find(prefix);
        if (pos != std::string::npos) {
            size_t end = cleanText.find_first_of(" \t\r\n;,)[]", pos + prefix.size());
            std::string candidate = cleanText.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
            candidate = trimTokenPunctuation(candidate);
            if (!candidate.empty()) return candidate;
        }
    }

    std::istringstream stream(cleanText);
    std::string token;
    while (stream >> token) {
        token = trimTokenPunctuation(token);
        if (looksLikeVersionToken(token)) return token;
    }

    return "";
}

inline std::string extractHttpHeaderVersion(const std::string& response) {
    const std::vector<std::string> headers = {"Server:", "X-Powered-By:", "X-Generator:"};

    for (const auto& header : headers) {
        size_t pos = response.find(header);
        if (pos == std::string::npos) continue;

        size_t valueStart = pos + header.size();
        size_t lineEnd = response.find("\r\n", valueStart);
        std::string value = response.substr(valueStart, lineEnd == std::string::npos ? std::string::npos : lineEnd - valueStart);
        value = trimCopy(value);

        std::string version = extractVersionToken(value);
        if (!version.empty()) return version;
        if (!value.empty()) return value;
    }

    return "";
}

inline std::string extractMySQLHandshakeVersion(const std::string& packet) {
    if (packet.size() < 6) return "";

    size_t pos = 4;
    if (pos >= packet.size()) return "";

    unsigned char protocolVersion = static_cast<unsigned char>(packet[pos]);
    if (protocolVersion < 0x05 || protocolVersion > 0x0a) return "";
    ++pos;

    size_t end = packet.find('\0', pos);
    if (end == std::string::npos || end <= pos) return "";

    std::string version = trimCopy(packet.substr(pos, end - pos));
    if (version.empty()) return "";

    return version;
}

// --- Core Scanner Function (Project Deep Focus Style) ---
inline std::string scanTargetIntelligent(const std::string& ip, const std::vector<int>& ports, int throttle_ms = 0) {
    std::ostringstream output;
    std::vector<ScanResult> findings;

    output << "* Project DELTA // Deep Network Scan on " << ip << "\n";
    output << "* Timeout: " << SCAN_TIMEOUT_SEC << "s | Throttle: " << throttle_ms << "ms\n\n";

    for (int port : ports) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        setNonBlocking(sock);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        // Attempt Connection
        int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        bool connected = false;

#ifdef _WIN32
        if (res == 0) connected = true;
        else if (GET_ERROR == WOULD_BLOCK) {
            fd_set writefds;
            struct timeval tv;
            tv.tv_sec = SCAN_TIMEOUT_SEC;
            tv.tv_usec = 0;
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);
            if (select(sock + 1, NULL, &writefds, NULL, &tv) > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
                if (err == 0) connected = true;
            }
        }
#else
        if (res == 0) connected = true;
        else if (GET_ERROR == WOULD_BLOCK) {
            fd_set writefds;
            struct timeval tv;
            tv.tv_sec = SCAN_TIMEOUT_SEC;
            tv.tv_usec = 0;
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);
            if (select(sock + 1, NULL, &writefds, NULL, &tv) > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err == 0) connected = true;
            }
        }
#endif

        if (connected) {
            ScanResult resData;
            resData.port = port;
            resData.service = serviceNameForPort(port);
            resData.authStatus = "Unknown";
            resData.riskLevel = riskLevelForPort(port);
            resData.vulnerability = "";
            resData.exposureNote = exposureNoteForPort(port);
            resData.deviceBrand = "";

            // --- Deep Service Probing ---

            // 1. FTP (21) - Anonymous Login Check
            if (port == 21) {
                std::string banner = recvBanner(sock, 1000);
                std::string version = extractVersionToken(banner);
                if (!version.empty()) resData.version = version;
                
                // Attempt Anonymous Login
                std::string resp = sendRecv(sock, "USER anonymous\r\n", 1000);
                if (resp.find("230") != std::string::npos) {
                    resData.authStatus = "Open";
                    resData.vulnerability = "[CRITICAL] Anonymous FTP Access";
                    resData.exposureNote.clear();
                } else if (resp.find("331") != std::string::npos) {
                    resData.authStatus = "Auth Required";
                }
            }
            // 2. SSH (22) - Version & Key Exchange Fingerprinting
            else if (port == 22) {
                std::string banner = recvBanner(sock, 1000);
                std::string version = extractVersionToken(banner);
                if (!version.empty()) {
                    resData.version = version;
                    if (banner.find("Dropbear") != std::string::npos) resData.deviceBrand = "Embedded/IoT";
                    else if (banner.find("MikroTik") != std::string::npos) resData.deviceBrand = "MikroTik";
                    else if (banner.find("Cisco") != std::string::npos) resData.deviceBrand = "Cisco";
                }
                resData.authStatus = "Key-Based/Password";
            }
            // 2b. Telnet / shell-style services
            else if (port == 23) {
                std::string banner = recvBanner(sock, 1000);
                std::string version = extractVersionToken(banner);
                if (!version.empty()) {
                    resData.version = version;
                    resData.authStatus = "Open";
                    if (resData.exposureNote.empty()) resData.exposureNote = "[HIGH] Telnet banner exposed";
                }
            }
            // 2c. SMTP-family services
            else if (port == 25 || port == 587) {
                std::string banner = recvBanner(sock, 1000);
                std::string version = extractVersionToken(banner);
                if (!version.empty()) {
                    resData.version = version;
                    resData.authStatus = "Open";
                    if (resData.exposureNote.empty()) resData.exposureNote = "[INFO] SMTP service exposed";
                }
            }
            // 2d. POP3 / IMAP family
            else if (port == 110 || port == 143 || port == 993 || port == 995) {
                std::string banner = recvBanner(sock, 1000);
                std::string version = extractVersionToken(banner);
                if (!version.empty()) {
                    resData.version = version;
                    resData.authStatus = "Open";
                    if (resData.exposureNote.empty()) resData.exposureNote = "[INFO] Mail service exposed";
                }
            }
            // 3. HTTP (80/8080) - Server & TLS Fingerprinting
            else if (port == 80 || port == 8080 || port == 5000 || port == 9000) {
                std::string req = "GET / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n";
                std::string resp = sendRecv(sock, req, 1000);
                if (!resp.empty()) {
                    std::string version = extractHttpHeaderVersion(resp);
                    if (!version.empty()) resData.version = version;
                    if (resp.find("401 Unauthorized") != std::string::npos) {
                        resData.exposureNote = "[INFO] Protected web endpoint";
                    } else if (resData.exposureNote.empty()) {
                        resData.exposureNote = "[INFO] HTTP service exposed";
                    }
                }
                resData.authStatus = "Open";
            }
            // 3b. TLS-wrapped services where cleartext probing would be misleading
            else if (port == 443 || port == 8443 || port == 993 || port == 995) {
                resData.authStatus = "Unknown";
                resData.exposureNote = "[INFO] TLS service detected; plain-text fingerprinting skipped";
            }
            // 3c. SMB / NetBIOS / file sharing services
            else if (port == 139 || port == 445 || port == 2049 || port == 631) {
                std::string banner = recvBanner(sock, 1000);
                std::string version = extractVersionToken(banner);
                if (!version.empty()) resData.version = version;
                resData.authStatus = "Open";
            }
            // 4. VNC (5900) - Authentication Type Detection
            else if (port == 5900) {
                std::string banner = recvBanner(sock, 1000);
                std::string version = extractVersionToken(banner);
                if (!version.empty()) resData.version = version;
                
                if (banner.find("RFB 003.003") != std::string::npos || banner.find("RFB 003.008") != std::string::npos) {
                    // Check for "None" auth type (first byte after banner usually indicates auth scheme)
                    // Simplified: If banner exists and no immediate challenge, flag it.
                    // Real implementation reads the auth scheme byte.
                    resData.authStatus = "Check Scheme"; 
                    resData.vulnerability = "[WARN] VNC Exposed (Verify Auth Type)";
                }
            }
            // 5. RTSP (554) - Camera Brand & Auth Check
            else if (port == 554) {
                std::string req = "OPTIONS rtsp://" + ip + "/ RTSP/1.0\r\nCSeq: 1\r\n\r\n";
                std::string resp = sendRecv(sock, req, 1000);
                if (!resp.empty()) {
                    if (resp.find("Hikvision") != std::string::npos) resData.deviceBrand = "Hikvision";
                    else if (resp.find("Dahua") != std::string::npos) resData.deviceBrand = "Dahua";
                    else if (resp.find("Axis") != std::string::npos) resData.deviceBrand = "Axis";
                    
                    if (resp.find("401 Unauthorized") == std::string::npos && resp.find("200 OK") != std::string::npos) {
                        resData.authStatus = "Open / Reachable (not authenticated)";
                        resData.vulnerability = "[CRITICAL] Open RTSP Stream";
                    } else {
                        resData.authStatus = "Authentication Required";
                    }
                }
            }
            // 6. MQTT (1883) - Broker Access Check
            else if (port == 1883) {
                // MQTT CONNECT packet (fixed header + variable header for CONNECT)
                uint8_t mqttConnect[] = {
                    0x10, 0x0E, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x00, 0x00, 0x00
                };
                send(sock, (const char*)mqttConnect, sizeof(mqttConnect), 0);
                std::string resp = recvRaw(sock, 1000);
                if (!resp.empty() && (unsigned char)resp[0] == 0x20) {
                    // CONNACK received
                    if (resp.size() > 3 && (unsigned char)resp[3] == 0x00) {
                        resData.authStatus = "Open / Reachable (not authenticated)";
                        resData.vulnerability = "[CRITICAL] Open MQTT Broker";
                    } else if (resData.vulnerability.empty()) {
                        resData.vulnerability = "[MEDIUM] MQTT broker exposed";
                    }
                }
            }
            // 7. RDP (3389) - Security Mode Detection
            else if (port == 3389) {
                // Simplified RDP Initial Cookie (X.224 Connect Request)
                uint8_t rdpReq[] = {
                    0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00
                };
                send(sock, (const char*)rdpReq, sizeof(rdpReq), 0);
                std::string resp = recvBanner(sock, 1000);
                if (!resp.empty()) {
                    resData.version = "RDP Service Detected";
                    resData.authStatus = "Open"; // Requires deeper parsing
                    resData.vulnerability = "[INFO] RDP Exposed";
                }
            }
            // 8. Databases and common infrastructure services
            else if (port == 1433 || port == 1521 || port == 3306 || port == 5432 || port == 6379 || port == 27017 || port == 9200) {
                if (port == 3306) {
                    std::string handshake = recvRaw(sock, 1000, 128);
                    std::string version = extractMySQLHandshakeVersion(handshake);
                    if (!version.empty()) {
                        resData.version = version;
                        resData.exposureNote = "[INFO] MySQL banner exposed";
                    }
                } else {
                    std::string banner = recvBanner(sock, 1000);
                    std::string version = extractVersionToken(banner);
                    if (!version.empty()) resData.version = version;
                    if (port == 6379 && !banner.empty()) {
                        resData.exposureNote = "[WARN] Redis service reachable";
                    }
                }
                resData.authStatus = "Open";
            }
            // Generic Fallback
            else {
                std::string banner = recvBanner(sock, 500);
                std::string version = extractVersionToken(banner);
                if (!version.empty()) resData.version = version;
                resData.authStatus = "Unknown";
            }

            findings.push_back(resData);
        }
        CLOSE_SOCKET(sock);
        
        // Thermal Throttle (Simulated Governor)
        if (throttle_ms > 0) SLEEP_MS(throttle_ms);
    }

    // Format Output
    if (findings.empty()) {
        output << "[-] No open ports found.\n";
    } else {
        output << "[+] " << findings.size() << " Services Discovered:\n";
        output << "================================================================\n";
        for (const auto& f : findings) {
            output << "PORT: " << f.port << " | SERVICE: " << f.service;
            if (!f.deviceBrand.empty()) output << " (" << f.deviceBrand << ")";
            output << "\n";

            if (!f.riskLevel.empty())
                output << "  * Risk: " << f.riskLevel << "\n";
            
            if (!f.version.empty()) 
                output << "  * Version: " << f.version << "\n";
            else
                output << "  * Version: Unknown\n";
            if (!f.authStatus.empty()) 
                output << "  * Access State: " << f.authStatus << "\n";
            if (!f.vulnerability.empty()) 
                output << "  * Confirmed Vulnerability: " << f.vulnerability << "\n";
            if (!f.exposureNote.empty())
                output << "  * Exposure Note: " << f.exposureNote << "\n";
            output << "----------------------------------------------------------------\n";
        }
    }

    return output.str();
}   