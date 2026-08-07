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
#endif

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
            result << typeStr << ipstr << "\n";
        }
        p = p->ai_next;
    }

    freeaddrinfo(res);
    return result.str();
}   