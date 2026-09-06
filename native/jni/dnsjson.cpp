#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>

#pragma pack(push, 1)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

// Converts "example.com" -> "\x07example\x03com\x00"
void format_domain(const std::string& domain, std::vector<uint8_t>& buf) {
    size_t start = 0;
    size_t end = domain.find('.');
    while (end != std::string::npos) {
        buf.push_back(static_cast<uint8_t>(end - start));
        for (size_t i = start; i < end; ++i) buf.push_back(domain[i]);
        start = end + 1;
        end = domain.find('.', start);
    }
    buf.push_back(static_cast<uint8_t>(domain.length() - start));
    for (size_t i = start; i < domain.length(); ++i) buf.push_back(domain[i]);
    buf.push_back(0x00);
}

// Queries a specific DNS record type (1 = A, 28 = AAAA)
bool perform_dns_query(const std::string& domain, const std::string& server_ip, uint16_t qtype, std::vector<std::string>& out_ips) {
    bool is_ipv6_server = (server_ip.find(':') != std::string::npos);
    int domain_family = is_ipv6_server ? AF_INET6 : AF_INET;

    int sock = socket(domain_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return false;

    struct timeval timeout{2, 0}; // 2-second socket timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Construct Packet Header
    DNSHeader header{};
    header.id = htons(0x4321);
    header.flags = htons(0x0100); // RD = 1
    header.qdcount = htons(1);

    std::vector<uint8_t> packet;
    uint8_t* h_ptr = reinterpret_cast<uint8_t*>(&header);
    packet.insert(packet.end(), h_ptr, h_ptr + sizeof(DNSHeader));

    format_domain(domain, packet);

    uint16_t type_net = htons(qtype);
    uint16_t class_net = htons(1); // IN Class
    uint8_t* t_ptr = reinterpret_cast<uint8_t*>(&type_net);
    uint8_t* c_ptr = reinterpret_cast<uint8_t*>(&class_net);
    packet.insert(packet.end(), t_ptr, t_ptr + 2);
    packet.insert(packet.end(), c_ptr, c_ptr + 2);

    // Send UDP packet
    bool send_ok = false;
    if (is_ipv6_server) {
        sockaddr_in6 dest6{};
        dest6.sin6_family = AF_INET6;
        dest6.sin6_port = htons(53);
        inet_pton(AF_INET6, server_ip.c_str(), &dest6.sin6_addr);
        send_ok = (sendto(sock, packet.data(), packet.size(), 0, (struct sockaddr*)&dest6, sizeof(dest6)) >= 0);
    } else {
        sockaddr_in dest4{};
        dest4.sin_family = AF_INET;
        dest4.sin_port = htons(53);
        inet_pton(AF_INET, server_ip.c_str(), &dest4.sin_addr);
        send_ok = (sendto(sock, packet.data(), packet.size(), 0, (struct sockaddr*)&dest4, sizeof(dest4)) >= 0);
    }

    if (!send_ok) {
        close(sock);
        return false;
    }

    uint8_t response[512];
    ssize_t res_len = recvfrom(sock, response, sizeof(response), 0, nullptr, nullptr);
    close(sock);

    if (res_len <= (ssize_t)sizeof(DNSHeader)) return false;

    // Check RCODE (Response code) in flags
    DNSHeader* res_header = reinterpret_cast<DNSHeader*>(response);
    uint16_t res_flags = ntohs(res_header->flags);
    if ((res_flags & 0x000F) != 0) return false; // Non-zero RCODE indicates error

    uint16_t ancount = ntohs(res_header->ancount);
    if (ancount == 0) return true; // Valid query, zero records found

    // Advance buffer index past header and Question section
    size_t idx = sizeof(DNSHeader);
    while (idx < (size_t)res_len && response[idx] != 0) {
        if ((response[idx] & 0xC0) == 0xC0) { idx += 2; break; } // Compression pointer
        idx += response[idx] + 1;
    }
    if (response[idx] == 0) idx += 1;
    idx += 4; // Skip QTYPE + QCLASS

    // Parse Answers
    for (int i = 0; i < ancount && idx < (size_t)res_len; ++i) {
        // Skip NAME field
        if ((response[idx] & 0xC0) == 0xC0) {
            idx += 2;
        } else {
            while (idx < (size_t)res_len && response[idx] != 0) idx += response[idx] + 1;
            idx++;
        }

        if (idx + 10 > (size_t)res_len) break;

        uint16_t rtype = ntohs(*reinterpret_cast<uint16_t*>(&response[idx]));
        uint16_t rdlength = ntohs(*reinterpret_cast<uint16_t*>(&response[idx + 8]));
        idx += 10; // Skip TYPE, CLASS, TTL, RDLENGTH

        if (idx + rdlength > (size_t)res_len) break;

        // Parse IPv4 (TYPE 1, length 4)
        if (rtype == 1 && rdlength == 4) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &response[idx], ip_str, sizeof(ip_str));
            out_ips.push_back(ip_str);
        }
        // Parse IPv6 (TYPE 28, length 16)
        else if (rtype == 28 && rdlength == 16) {
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &response[idx], ip_str, sizeof(ip_str));
            out_ips.push_back(ip_str);
        }

        idx += rdlength;
    }

    return true;
}

// Resolves a hostname via the system resolver (getaddrinfo -> netd on Android),
// used when no explicit DNS server is provided on the command line.
bool resolve_hostname_system(const std::string& hostname, std::vector<std::string>& ipv4_out, std::vector<std::string>& ipv6_out) {
    struct addrinfo hints{}, *res = nullptr;

    hints.ai_family = AF_UNSPEC;     // Accept both IPv4 and IPv6 results
    hints.ai_socktype = SOCK_STREAM; // TCP, doesn't affect address resolution

    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (status != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        return false;
    }

    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        char ipstr[INET6_ADDRSTRLEN];
        void* addr = nullptr;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
            addr = &(ipv4->sin_addr);
            inet_ntop(AF_INET, addr, ipstr, sizeof(ipstr));
            ipv4_out.push_back(ipstr);
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
            addr = &(ipv6->sin6_addr);
            inet_ntop(AF_INET6, addr, ipstr, sizeof(ipstr));
            ipv6_out.push_back(ipstr);
        }
    }

    freeaddrinfo(res);
    return true;
}

void print_json(bool error, const std::vector<std::string>& ipv4, const std::vector<std::string>& ipv6) {
    std::cout << "{\n";
    std::cout << "  \"error\": " << (error ? "true" : "false") << ",\n";
    
    std::cout << "  \"ipv4\": [";
    for (size_t i = 0; i < ipv4.size(); ++i) {
        std::cout << "\"" << ipv4[i] << "\"" << (i + 1 < ipv4.size() ? ", " : "");
    }
    std::cout << "],\n";

    std::cout << "  \"ipv6\": [";
    for (size_t i = 0; i < ipv6.size(); ++i) {
        std::cout << "\"" << ipv6[i] << "\"" << (i + 1 < ipv6.size() ? ", " : "");
    }
    std::cout << "]\n";
    std::cout << "}\n";
}

// argv[0] here is expected to be "dnsjson" (the subcommand name),
// argv[1] = domain, argv[2] (optional) = dns server IP.
int run_dnsjson(int argc, char* argv[]) {
    if (argc < 2) {
        print_json(true, {}, {});
        return 1;
    }

    std::string domain = argv[1];

    std::vector<std::string> ipv4_list;
    std::vector<std::string> ipv6_list;
    bool has_error;

    if (argc >= 3) {
        // Explicit DNS server given: use the manual UDP query path.
        std::string dns_server = argv[2];

        bool ok_v4 = perform_dns_query(domain, dns_server, 1, ipv4_list);   // A records
        bool ok_v6 = perform_dns_query(domain, dns_server, 28, ipv6_list); // AAAA records

        has_error = (!ok_v4 && !ok_v6);
    } else {
        // No DNS server specified: resolve via the system resolver (netd).
        bool ok = resolve_hostname_system(domain, ipv4_list, ipv6_list);
        has_error = !ok;
    }

    print_json(has_error, ipv4_list, ipv6_list);

    return has_error ? 1 : 0;
}