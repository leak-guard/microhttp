#pragma once
#include "leakguard/staticvector.hpp"
#include "staticstring.hpp"

#include <array>
#include <cctype>
#include <concepts>
#include <cstdint>
#include <functional>
#include <iostream>
#include <utility>

#ifndef HTTP_BUFFER_SIZE
#define HTTP_BUFFER_SIZE 1024
#endif

#ifndef HTTP_MAX_HEADERS
#define HTTP_MAX_HEADERS 25
#endif

#ifndef HTTP_MAX_HEADER_LENGTH
#define HTTP_MAX_HEADER_LENGTH 128
#endif

#ifndef HTTP_MAX_URL_LENGTH
#define HTTP_MAX_URL_LENGTH 64
#endif

#ifndef HTTP_TARGET_SEND_CHUNK_LENGTH
#define HTTP_TARGET_SEND_CHUNK_LENGTH 256
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
    t.close(std::declval<int>());
    { t.send(std::declval<int>(), 
        std::declval<const char*>(), 
        std::declval<std::size_t>()) } -> std::convertible_to<std::size_t>;
};

class HttpHeaders {
    template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
    friend class HttpServer;

public:
    using TagString = StaticString<32>;
    using ValueString = StaticString<HTTP_MAX_HEADER_LENGTH>;

    /**
     * @brief Adds a new entry to header list
     * 
     * @param tag header type (e.g. "Content-Type", "Content-Length" or "Set-Cookie")
     * @param value header value
     * @return true, if the operation succeeded,
     * @return false otherwise
     */
    bool add(const TagString& tag, const ValueString& value)
    {
        return m_headers.Append(std::make_pair(tag, value));
    }

    /**
     * @brief Clears header list
     * 
     */
    void clear()
    {
        m_headers.Clear();
    }

    /**
     * @brief Gets the number of headers currently stored in the list
     * 
     * @return number of headers
     */
    std::size_t size() const
    {
        return m_headers.GetSize();
    }

    /**
     * @brief Accesses a value of a single header by its tag
     * 
     * If no tag is found, a new one is added to the list.
     *
     * @param tag tag to search for
     * @return a reference to tag value
     */
    ValueString& operator[](const TagString& tag) {
        for (auto& element : m_headers) {
            if (element.first == tag) {
                return element.second;
            }
        }

        add(tag, ValueString());
        return m_headers[m_headers.GetSize() - 1].second;
    }

    /**
     * @brief Accesses a value of a single header by its tag
     * 
     * If no tag is found, `abort()` is called.
     *
     * @param tag tag to search for
     * @return a reference to tag value
     */
    const ValueString& operator[](const TagString& tag) const
    {
        for (auto& element : m_headers) {
            if (element.first == tag) {
                return element.second;
            }
        }

        abort();
    }

    /**
     * @brief Accesses a single header pair by its index number
     * 
     * @param index an index of the header
     * @return a reference to a header pair (tag, value)
     */
    auto& operator[](int index) {
        return m_headers[index];
    }

    /**
     * @brief Accesses a single header pair by its index number
     * 
     * @param index an index of the header
     * @return a reference to a header pair (tag, value)
     */
    const auto& operator[](int index) const {
        return m_headers[index];
    }

    /**
     * @brief Returns index of a first header with matching tag
     * 
     * @param tag tag to search for
     * @return index of the header, if the operation succeeded, otherwise -1
     */
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

    /**
     * @brief Returns an iterator to the beginning
     * 
     * @return an iterator to the beginning
     */
    auto begin() { return m_headers.begin(); }

    /**
     * @brief Returns a const iterator to the beginning
     * 
     * @return an iterator to the beginning
     */
    auto begin() const { return m_headers.begin(); }

    /**
     * @brief Returns an iterator to the end
     * 
     * @return an iterator to the end
     */
    auto end() { return m_headers.end(); }

    /**
     * @brief Returns a const iterator to the end
     * 
     * @return an iterator to the end
     */
    auto end() const { return m_headers.end(); }

private:
    StaticVector<std::pair<TagString, ValueString>, HTTP_MAX_HEADERS> m_headers;

    template <std::size_t n>
    bool parseAndAdd(const StaticString<n>& line)
    {
        enum class Stage {
            LTRIM,
            TAG,
            MTRIM,
            VALUE
        };

        TagString tag;
        ValueString value;
        Stage stage = Stage::LTRIM;

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
                        valueLength = value.GetSize();
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
        if (!tag.IsEmpty() && !value.IsEmpty()) {
            add(tag, value);
            return true;
        } else {
            return false;
        }
    }
};

/**
 * @brief An enum defining supported HTTP methods
 * 
 */
enum class HttpMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE
};

/**
 * @brief An enum containing all standard-defined HTTP status codes
 * 
 */
enum class HttpStatusCode {
  // Information responses
  Continue_100 = 100,
  SwitchingProtocol_101 = 101,
  Processing_102 = 102,
  EarlyHints_103 = 103,

  // Successful responses
  OK_200 = 200,
  Created_201 = 201,
  Accepted_202 = 202,
  NonAuthoritativeInformation_203 = 203,
  NoContent_204 = 204,
  ResetContent_205 = 205,
  PartialContent_206 = 206,
  MultiStatus_207 = 207,
  AlreadyReported_208 = 208,
  IMUsed_226 = 226,

  // Redirection messages
  MultipleChoices_300 = 300,
  MovedPermanently_301 = 301,
  Found_302 = 302,
  SeeOther_303 = 303,
  NotModified_304 = 304,
  UseProxy_305 = 305,
  unused_306 = 306,
  TemporaryRedirect_307 = 307,
  PermanentRedirect_308 = 308,

  // Client error responses
  BadRequest_400 = 400,
  Unauthorized_401 = 401,
  PaymentRequired_402 = 402,
  Forbidden_403 = 403,
  NotFound_404 = 404,
  MethodNotAllowed_405 = 405,
  NotAcceptable_406 = 406,
  ProxyAuthenticationRequired_407 = 407,
  RequestTimeout_408 = 408,
  Conflict_409 = 409,
  Gone_410 = 410,
  LengthRequired_411 = 411,
  PreconditionFailed_412 = 412,
  PayloadTooLarge_413 = 413,
  UriTooLong_414 = 414,
  UnsupportedMediaType_415 = 415,
  RangeNotSatisfiable_416 = 416,
  ExpectationFailed_417 = 417,
  ImATeapot_418 = 418,
  MisdirectedRequest_421 = 421,
  UnprocessableContent_422 = 422,
  Locked_423 = 423,
  FailedDependency_424 = 424,
  TooEarly_425 = 425,
  UpgradeRequired_426 = 426,
  PreconditionRequired_428 = 428,
  TooManyRequests_429 = 429,
  RequestHeaderFieldsTooLarge_431 = 431,
  UnavailableForLegalReasons_451 = 451,

  // Server error responses
  InternalServerError_500 = 500,
  NotImplemented_501 = 501,
  BadGateway_502 = 502,
  ServiceUnavailable_503 = 503,
  GatewayTimeout_504 = 504,
  HttpVersionNotSupported_505 = 505,
  VariantAlsoNegotiates_506 = 506,
  InsufficientStorage_507 = 507,
  LoopDetected_508 = 508,
  NotExtended_510 = 510,
  NetworkAuthenticationRequired_511 = 511,
};


/**
 * @brief A struct that contains attributes of a single HTTP request
 * 
 */
struct HttpRequest {
    /**
     * @brief Request method
     * 
     */
    const HttpMethod method;

    /**
     * @brief Request URL
     * 
     */
    const StaticString<HTTP_MAX_URL_LENGTH>& url;

    /**
     * @brief Request headers
     * 
     */
    const HttpHeaders& headers;

    /**
     * @brief Request body
     * 
     */
    const StaticString<HTTP_BUFFER_SIZE>& body;
};

/**
 * @brief A class that contains attributes of a single HTTP response
 * 
 */
class HttpResponse {
public:
    HttpResponse& status(int status)
    {
        m_status = static_cast<HttpStatusCode>(status);
        return *this;
    }

    HttpResponse& status(HttpStatusCode status)
    {
        m_status = status;
        return *this;
    }

private:
    HttpStatusCode m_status { HttpStatusCode::OK_200 };
};

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
class HttpServer : public HttpServerBase {
public:
    using RequestHandler = std::function<void(HttpRequest&, HttpResponse&)>;

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

    // Request handler registration

    /**
     * @brief Register a new GET request handler
     *
     * Note that GET requests have no body.
     * 
     * @param route route to handle
     * @param handler a handler that processes HttpRequest and produces HttpResponse
     */
    void get(const char* route, RequestHandler handler)
    {
        registerHandler(HttpMethod::GET, route, handler);
    }

    /**
     * @brief Register a new POST request handler
     * 
     * @param route route to handle
     * @param handler a handler that processes HttpRequest and produces HttpResponse
     */
    void post(const char* route, RequestHandler handler)
    {
        registerHandler(HttpMethod::POST, route, handler);
    }

    /**
     * @brief Register a new PUT request handler
     * 
     * @param route route to handle
     * @param handler a handler that processes HttpRequest and produces HttpResponse
     */
    void put(const char* route, RequestHandler handler)
    {
        registerHandler(HttpMethod::PUT, route, handler);
    }

    /**
     * @brief Register a new PATCH request handler
     * 
     * @param route route to handle
     * @param handler a handler that processes HttpRequest and produces HttpResponse
     */
    void patch(const char* route, RequestHandler handler)
    {
        registerHandler(HttpMethod::PATCH, route, handler);
    }

    /**
     * @brief Register a new DELETE request handler
     *
     * `delete` is a reserved C++ keyword and thus cannot be used as a method name.
     * 
     * @param route route to handle
     * @param handler a handler that processes HttpRequest and produces HttpResponse
     */
    void del(const char* route, RequestHandler handler)
    {
        registerHandler(HttpMethod::DELETE, route, handler);
    }

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
        StaticString<HTTP_MAX_URL_LENGTH> m_requestUrl {};
        HttpHeaders m_requestHeaders {};
        std::size_t m_contentLength {};

        void processLine();
    };

    SocketImpl_t m_socketImpl;
    std::array<Connection, MAX_CONNECTIONS> m_connections;

    void registerHandler(HttpMethod method, const char* route, RequestHandler handler);
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
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::registerHandler(
    HttpMethod method, const char* route, RequestHandler handler)
{

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
    m_contentLength = 0;
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::Connection::recvBytes(
    const char* data, std::size_t numBytes)
{
    while (numBytes) {
        if (m_state == ConnectionState::FINISHED || m_state == ConnectionState::DISCARDED) {
            return;
        }

        bool isParsingLineByLine = m_state < ConnectionState::REQUEST_BODY;
        ConnectionState initialState = m_state;

        if (isParsingLineByLine) {
            while (numBytes) {
                m_buffer += *(data++);
                --numBytes;

                int bufferSize = m_buffer.GetSize();

                if (bufferSize >= 2 
                    && m_buffer[bufferSize - 2] == '\r' 
                    && m_buffer[bufferSize - 1] == '\n') {

                    m_buffer.Truncate(bufferSize - 2);
                    processLine();
                    m_buffer.Clear();

                    if (m_state != initialState) {
                        break;
                    }
                }
            }
        }

        if (m_state == ConnectionState::REQUEST_BODY) {
            while (m_buffer.GetSize() < m_contentLength && numBytes) {
                m_buffer += *(data++);
                --numBytes;
            }

            if (m_buffer.GetSize() == m_contentLength) {
                std::cout << m_buffer.ToCStr() << std::endl;
                const char* text = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                m_server->m_socketImpl.send(m_connectionId, text, strlen(text));
                m_server->m_socketImpl.close(m_connectionId);
                m_state = ConnectionState::FINISHED;
            }
        }
    }
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::Connection::processLine()
{
    switch (m_state) {
    case ConnectionState::URI_AND_METHOD:
    {
        static const std::array METHODS = {
            StaticString<8>("GET "),
            StaticString<8>("POST "),
            StaticString<8>("PUT "),
            StaticString<8>("PATCH "),
            StaticString<8>("DELETE "),
        };

        bool foundMethod = false;
        for (size_t i = 0; i < METHODS.size(); ++i) {
            if (m_buffer.StartsWith(METHODS[i])) {
                m_requestMethod = static_cast<HttpMethod>(i);
                m_buffer.Skip(METHODS[i].GetLength());
                foundMethod = true;
                break;
            }
        }

        if (!foundMethod) {
            m_server->m_socketImpl.close(m_connectionId);
            discard();
            return;
        }

        // Cut off HTTP version and query params
        for (int i = 0; i < m_buffer.GetSize(); ++i) {
            char c = m_buffer[i];
            if (std::isspace(c) || c == '?') {
                m_buffer.Truncate(i);
                break;
            }
        }

        m_requestUrl = m_buffer;
        
        m_state = ConnectionState::REQUEST_HEADERS;
        break;
    }
    case ConnectionState::REQUEST_HEADERS:
        if (!m_requestHeaders.parseAndAdd(m_buffer)) {
            m_state = ConnectionState::REQUEST_BODY;
        } else if (m_requestHeaders[m_requestHeaders.size() - 1].first == STR("content-length")) {
            m_contentLength = m_requestHeaders[
                m_requestHeaders.size() - 1].second.ToInteger<std::size_t>();
        }
        break;
    default:
        break;
    }
}

};
