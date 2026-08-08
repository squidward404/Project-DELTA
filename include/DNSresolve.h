// include/DNSResolve.h
#pragma once

#include <string>
#include <cstring>
#include <sstream>
#include <vector>

// Platform specific headers
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

#ifdef _WIN32
inline void closeSocketCompat(int sock) { closesocket(sock); }
#else
inline void closeSocketCompat(int sock) { close(sock); }
#endif

inline std::string httpGetText(const std::string& host, const std::string& path) {
    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), "80", &hints, &res) != 0) {
        return "";
    }

    std::string response;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        int sock = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;

        if (connect(sock, p->ai_addr, (int)p->ai_addrlen) == 0) {
            std::ostringstream request;
            request << "GET " << path << " HTTP/1.0\r\n"
                    << "Host: " << host << "\r\n"
                    << "User-Agent: ProjectDELTA\r\n"
                    << "Connection: close\r\n\r\n";

            std::string req = request.str();
            send(sock, req.c_str(), (int)req.size(), 0);

            char buffer[2048];
            int bytes = 0;
            while ((bytes = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
                response.append(buffer, buffer + bytes);
            }
            closeSocketCompat(sock);
            break;
        }

        closeSocketCompat(sock);
    }

    freeaddrinfo(res);

    size_t bodyPos = response.find("\r\n\r\n");
    if (bodyPos == std::string::npos) return "";
    return response.substr(bodyPos + 4);
}

inline std::string lookupCountryForIP(const std::string& ip) {
    // Best-effort geolocation lookup. Falls back to Unknown if the service is unreachable.
    std::string body = httpGetText("ip-api.com", "/json/" + ip + "?fields=status,country");
    if (body.empty()) return "Unknown";

    size_t countryPos = body.find("\"country\":\"");
    if (countryPos == std::string::npos) return "Unknown";
    countryPos += 11;
    size_t countryEnd = body.find('"', countryPos);
    if (countryEnd == std::string::npos) return "Unknown";
    return body.substr(countryPos, countryEnd - countryPos);
}

// 'inline' is critical for header-only functions to avoid linker errors
inline std::string resolveDomainDetailed(const std::string& domain) {
    std::ostringstream result;
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;      // IPv4 & IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;    // Resolve CNAME

    int status = getaddrinfo(domain.c_str(), NULL, &hints, &res);
    if (status != 0) {
        return "[Error] Resolution failed: " + std::string(gai_strerror(status));
    }

    // 1. Detect CNAME
    if (res->ai_canonname && strcmp(res->ai_canonname, domain.c_str()) != 0) {
        result << "[CNAME] " << domain << "  -->  " << res->ai_canonname << "\n";
    }

    // 2. Detect A / AAAA
    struct addrinfo* p = res;
    while(p != NULL) {
        char ipstr[INET6_ADDRSTRLEN];
        std::string typeStr = "";

        if (p->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            inet_ntop(p->ai_family, &(ipv4->sin_addr), ipstr, sizeof ipstr);
            typeStr = "[A]    "; 
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            inet_ntop(p->ai_family, &(ipv6->sin6_addr), ipstr, sizeof ipstr);
            typeStr = "[AAAA] "; 
        }

        if (!typeStr.empty()) {
            std::string country = lookupCountryForIP(ipstr);
            result << typeStr << ipstr << "  [Country] " << country << "\n";
        }
        p = p->ai_next;
    }

    freeaddrinfo(res);
    return result.str();
}   