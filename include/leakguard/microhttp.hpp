#pragma once
#include "leakguard/staticvector.hpp"
#include "staticstring.hpp"

#include <array>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>

#ifndef HTTP_BUFFER_SIZE
#define HTTP_BUFFER_SIZE 1024
#endif

#ifndef HTTP_MAX_HEADERS
#define HTTP_MAX_HEADERS 25
#endif

#ifndef HTTP_MAX_HEADER_LENGTH
#define HTTP_MAX_HEADER_LENGTH 256
#endif

namespace lg {

/**
 * @brief An interface providing methods to communicate events from
 *        socket implementation back to the server.
 */
class HttpServerBase {
public:
    /**
     * @brief A default virtual destructor
     * 
     */
    virtual ~HttpServerBase() = default;

    /**
     * @brief Notify the server that a new TCP client has arrived
     * 
     * @param connectionId unique ID of this connection
     */
    virtual void clientConnected(int connectionId) = 0;

    /**
     * @brief Notify the server that a TCP client has left, no matter
     *        what is the reason.
     * 
     * @param connectionId unique ID of this connection
     */
    virtual void clientDisconnected(int connectionId) = 0;

    /**
     * @brief Notify the server that a pack of bytes has arrived on a
     *        specific TCP socket
     * 
     * @param connectionId unique ID of this connection
     * @param data a C-style pointer to data
     * @param numBytes number of bytes
     */
    virtual void recvBytes(int connectionId, const char* data, std::size_t numBytes) = 0;
};

template <typename T>
concept SocketImpl = requires(T t) {
    T(std::declval<HttpServerBase&>());
    t.init();
    t.bind(std::declval<std::uint16_t>());
};

class HttpHeaders {
    template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
    friend class HttpServer;

public:
    using TagString = StaticString<32>;
    using ValueString = StaticString<HTTP_MAX_HEADER_LENGTH>;

    bool add(const TagString& tag, const ValueString& value)
    {
        return m_headers.Append(std::make_pair(tag, value));
    }

    void clear()
    {
        m_headers.Clear();
    }

    std::size_t size() const
    {
        return m_headers.GetSize();
    }

    ValueString& operator[](const TagString& tag) {
        for (auto& element : m_headers) {
            if (element.first == tag) {
                return element.second;
            }
        }

        add(tag, ValueString());
        return m_headers[m_headers.GetSize() - 1].second;
    }

    const ValueString& operator[](const TagString& tag) const
    {
        for (auto& element : m_headers) {
            if (element.first == tag) {
                return element.second;
            }
        }

        abort();
    }

    ValueString& operator[](int index) {
        return m_headers[index].second;
    }

    const ValueString& operator[](int index) const {
        return m_headers[index].second;
    }

    int find(const TagString& tag) const 
    {
        int i = 0;
        for (auto& element : m_headers) {
            if (element.first == tag) {
                return i;
            }

            ++i;
        }
        return -1;
    }

    auto begin() { return m_headers.begin(); }
    auto begin() const { return m_headers.begin(); }
    auto end() { return m_headers.begin(); }
    auto end() const { return m_headers.begin(); }

private:
    StaticVector<std::pair<TagString, ValueString>, HTTP_MAX_HEADERS> m_headers;

    template <std::size_t n>
    void parseAndAdd(const StaticString<n>& line)
    {
        enum class Stage {
            LTRIM,
            TAG,
            MTRIM,
            VALUE
        };

        TagString tag;
        ValueString value;
        Stage stage;

        std::size_t valueLength = 0;
        for (auto c : line) {
            switch (stage) {
                case Stage::LTRIM:
                    if (!std::isspace(c)) {
                        tag += std::tolower(c);
                        stage = Stage::TAG;
                    }
                    break;
                case Stage::TAG:
                    if (c == ':') {
                        stage = Stage::MTRIM;
                    } else {
                        tag += std::tolower(c);
                    }
                    break;
                case Stage::MTRIM:
                    if (!std::isspace(c)) {
                        value += std::tolower(c);
                        stage = Stage::VALUE;
                    }
                    break;
                case Stage::VALUE:
                    value += std::tolower(c);
                    if (!std::isspace(c)) {
                        valueLength = value.GetSize();
                    }
                    break;
            }
        }

        value.Truncate(valueLength);
        add(tag, value);
    }
};

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
class HttpServer : public HttpServerBase {
public:
    /**
     * @brief Default ctor
     * 
     */
    HttpServer();
    
    /**
     * @brief Start listening on a selected port, this function is blocking!
     * 
     * @param port a port to start listening on
     */
    void start(std::uint16_t port = 80);

    // Virtual methods
    void clientConnected(int connectionId) override;
    void clientDisconnected(int connectionId) override;

    void recvBytes(int connectionId, const char* data, std::size_t numBytes) override;

private:
    class Connection {
        friend class HttpServer;

    public:
        Connection()
        {
        }

        void setConnectionId(int connectionId)
        {
            m_connectionId = connectionId;
        }

        void setServer(HttpServer& server)
        {
            m_server = &server;
        }
        
        void discard();
        void reset();

        void recvBytes(const char* data, std::size_t numBytes);

    private:
        enum class HttpMethod {
            GET,
            POST,
            PUT,
            PATCH,
            DELETE
        };

        enum class ConnectionState {
            URI_AND_METHOD,
            REQUEST_HEADERS,
            REQUEST_BODY,
            RESPONSE_CODE,
            RESPONSE_HEADERS,
            RESPONSE_BODY,
            FINISHED,
            DISCARDED,
        };

        int m_connectionId {};
        HttpServer* m_server {};
        ConnectionState m_state { ConnectionState::URI_AND_METHOD };
        StaticString<HTTP_BUFFER_SIZE> m_buffer { };

        HttpMethod m_requestMethod {};
        StaticString<64> m_requestUrl {};
        HttpHeaders m_requestHeaders {};
        std::size_t contentLength {};
    };

    SocketImpl_t m_socketImpl;
    std::array<Connection, MAX_CONNECTIONS> m_connections;
};

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
HttpServer<SocketImpl_t, MAX_CONNECTIONS>::HttpServer()
    : m_socketImpl(*this)
{
    int i = 0;
    for (auto& connection : m_connections) {
        connection.setConnectionId(i);
        connection.setServer(*this);
        ++i;
    }

    m_socketImpl.init();
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::start(std::uint16_t port)
{
    m_socketImpl.bind(port);
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::clientConnected(int connectionId)
{
    if (connectionId >= m_connections.size()) {
        m_socketImpl.close(connectionId);
    }

    m_connections.at(connectionId).reset();
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::clientDisconnected(int connectionId)
{
    m_connections.at(connectionId).discard();
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::recvBytes(int connectionId, 
    const char* data, std::size_t numBytes)
{
    m_connections.at(connectionId).recvBytes(data, numBytes);
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::Connection::discard()
{
    m_state = ConnectionState::DISCARDED;
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::Connection::reset()
{
    m_state = ConnectionState::URI_AND_METHOD;
    m_requestUrl.Clear();
    m_requestHeaders.clear();
    contentLength = 0;
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::Connection::recvBytes(
    const char* data, std::size_t numBytes)
{
    std::cout << m_connectionId << std::endl;
}

};
