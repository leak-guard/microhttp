#include <leakguard/microhttp.hpp>

#include <array>
#include <cerrno>
#include <iostream>

// Linux system headers
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

class LinuxSocketImpl
{
public:
    static constexpr auto MAX_CONNECTIONS = 16;

    LinuxSocketImpl(lg::HttpServerBase& server)
        : m_server(server)
    {
        std::cout << "SocketImpl initialized" << std::endl;
    }

    void init()
    {
    }

    void bind(std::uint16_t port)
    {
        // How many clients may wait in connection queue
        static constexpr auto MAX_BACKLOG = 16;

        sockaddr_in addr = { 0 };
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = ::htons(port);
        addr.sin_family = AF_INET;

        sockaddr* sockAddr = reinterpret_cast<sockaddr*>(&addr);

        m_serverFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (!m_serverFd) {
            std::cerr << "Error while calling socket function" << std::endl;
            exit(-1);
        }

        int option = 1;
        if (::setsockopt(m_serverFd, SOL_SOCKET, 
        SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option))) {

            std::cerr << "Error while calling setsockopt function" << std::endl;
            ::exit(-2);
        }

        if (::bind(m_serverFd, sockAddr, sizeof(addr)) < 0) {
            std::cerr << "Error while calling bind function" << std::endl;
            ::exit(-3);
        }

        if (::listen(m_serverFd, MAX_BACKLOG) < 0) {
            std::cerr << "Error while calling listen function" << std::endl;
            ::exit(-4);
        }

        std::cout << "Server listening on port " << port << std::endl;
        std::cout << "Waiting for connections..." << std::endl;

        socklen_t addrLength = sizeof(addr);
        char buffer[1024];
        while (true) {
            int connectionFd = ::accept(m_serverFd, sockAddr, &addrLength);
            if (connectionFd > 0) {
                std::cout << "Got a new connection" << std::endl;

                for (int i = 0; i < MAX_CONNECTIONS; ++i) {
                    if (!m_connectionSlot.at(i)) {
                        m_connectionFd.at(i) = connectionFd;
                        m_connectionSlot.at(i) = true;
                        m_server.clientConnected(i);
                        break;
                    }
                }

                continue;
            }

            std::array<pollfd, MAX_CONNECTIONS> sockets = { 0 };
            int socketCount = 0;
            for (int i = 0; i < MAX_CONNECTIONS; ++i) {
                if (m_connectionSlot.at(i)) {
                    sockets.at(socketCount).fd = m_connectionFd.at(i);
                    sockets.at(socketCount).events = POLLIN;
                    ++socketCount;
                }
            }

            int pollVal = ::poll(sockets.data(), socketCount, TIMEOUT_MS);
            if (pollVal != -1) {
                for (int i = 0; i < MAX_CONNECTIONS; ++i) {
                    if (m_connectionSlot.at(i) && (sockets.at(i).revents & POLLIN)) {
                        int n = ::recv(m_connectionFd.at(i), 
                            buffer, sizeof(buffer), MSG_DONTWAIT);
                        
                        if (n > 0) {
                            m_server.recvBytes(i, buffer, static_cast<std::size_t>(n));
                        } else {
                            m_server.clientDisconnected(i);
                            m_connectionSlot.at(i) = false;
                            ::close(m_connectionFd.at(i));
                        }
                    }
                }
            }
        }
    }

    void close(int connectionId)
    {
        if (m_connectionSlot.at(connectionId)) {
            m_connectionSlot.at(connectionId) = false;
            ::close(m_connectionFd.at(connectionId));
        }
    }

    std::size_t send(int connectionId, const char* data, std::size_t numBytes)
    {
        if (m_connectionSlot.at(connectionId)) {
            int fd = m_connectionFd.at(connectionId);
            int n = ::send(fd, data, numBytes, 0);

            if (n < 0) {
                m_server.clientDisconnected(connectionId);
                m_connectionSlot.at(connectionId) = false;
                ::close(fd);
                return 0;
            }

            return static_cast<std::size_t>(n);
        }

        return 0;
    }

    void finish(int connectionId)
    {
        if (m_connectionSlot.at(connectionId)) {
            int fd = m_connectionFd.at(connectionId);
            ::shutdown(fd, SHUT_WR);
        }
    }

private:
    static constexpr auto TIMEOUT_MS = 500;

    lg::HttpServerBase& m_server;

    int m_serverFd {};
    std::array<int, MAX_CONNECTIONS> m_connectionFd {};
    std::array<bool, MAX_CONNECTIONS> m_connectionSlot {};
};

static_assert(lg::SocketImpl<LinuxSocketImpl>, 
    "LinuxSocketImpl does not satisfy SocketImpl concept");

int main()
{
    lg::HttpServer<LinuxSocketImpl, LinuxSocketImpl::MAX_CONNECTIONS> server;

    server.get("/", [&](lg::HttpRequest& req, lg::HttpResponse& res) {
        
    });

    server.get("/anytest/*", [&](lg::HttpRequest& req, lg::HttpResponse& res) {
        
    });

    server.get("/param/:1", [&](lg::HttpRequest& req, lg::HttpResponse& res) {

    });

    server.post("/withbody", [&](lg::HttpRequest& req, lg::HttpResponse& res) {
        
    });

    server.start(8080);
}
