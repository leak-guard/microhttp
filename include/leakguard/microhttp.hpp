#pragma once
#include "leakguard/staticstring.hpp"
#include "leakguard/staticvector.hpp"

#include <array>
#include <cctype>
#include <concepts>
#include <cstdint>
#include <functional>
#include <iostream>
#include <ostream>
#include <streambuf>
#include <string>
#include <utility>
#include <variant>
#include <vector>

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

#ifndef HTTP_REQUEST_PARAM_COUNT
#define HTTP_REQUEST_PARAM_COUNT 4
#endif

#ifndef HTTP_MAX_URL_PARTS
#define HTTP_MAX_URL_PARTS 8
#endif

#ifndef HTTP_TX_CHUNK_SIZE
#define HTTP_TX_CHUNK_SIZE 256
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
    t.finish(std::declval<int>());
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
    DELETE,
    METHOD_COUNT
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
 * @brief Gets HTTP Status Message for the provided Status Code
 * 
 * @param status status code for message lookup
 * @return a pointer to string literal
 */
inline constexpr const char* getHttpStatusMessage(HttpStatusCode status) {
  switch (status) {
  case HttpStatusCode::Continue_100: return "Continue";
  case HttpStatusCode::SwitchingProtocol_101: return "Switching Protocol";
  case HttpStatusCode::Processing_102: return "Processing";
  case HttpStatusCode::EarlyHints_103: return "Early Hints";
  case HttpStatusCode::OK_200: return "OK";
  case HttpStatusCode::Created_201: return "Created";
  case HttpStatusCode::Accepted_202: return "Accepted";
  case HttpStatusCode::NonAuthoritativeInformation_203:
    return "Non-Authoritative Information";
  case HttpStatusCode::NoContent_204: return "No Content";
  case HttpStatusCode::ResetContent_205: return "Reset Content";
  case HttpStatusCode::PartialContent_206: return "Partial Content";
  case HttpStatusCode::MultiStatus_207: return "Multi-Status";
  case HttpStatusCode::AlreadyReported_208: return "Already Reported";
  case HttpStatusCode::IMUsed_226: return "IM Used";
  case HttpStatusCode::MultipleChoices_300: return "Multiple Choices";
  case HttpStatusCode::MovedPermanently_301: return "Moved Permanently";
  case HttpStatusCode::Found_302: return "Found";
  case HttpStatusCode::SeeOther_303: return "See Other";
  case HttpStatusCode::NotModified_304: return "Not Modified";
  case HttpStatusCode::UseProxy_305: return "Use Proxy";
  case HttpStatusCode::unused_306: return "unused";
  case HttpStatusCode::TemporaryRedirect_307: return "Temporary Redirect";
  case HttpStatusCode::PermanentRedirect_308: return "Permanent Redirect";
  case HttpStatusCode::BadRequest_400: return "Bad Request";
  case HttpStatusCode::Unauthorized_401: return "Unauthorized";
  case HttpStatusCode::PaymentRequired_402: return "Payment Required";
  case HttpStatusCode::Forbidden_403: return "Forbidden";
  case HttpStatusCode::NotFound_404: return "Not Found";
  case HttpStatusCode::MethodNotAllowed_405: return "Method Not Allowed";
  case HttpStatusCode::NotAcceptable_406: return "Not Acceptable";
  case HttpStatusCode::ProxyAuthenticationRequired_407:
    return "Proxy Authentication Required";
  case HttpStatusCode::RequestTimeout_408: return "Request Timeout";
  case HttpStatusCode::Conflict_409: return "Conflict";
  case HttpStatusCode::Gone_410: return "Gone";
  case HttpStatusCode::LengthRequired_411: return "Length Required";
  case HttpStatusCode::PreconditionFailed_412: return "Precondition Failed";
  case HttpStatusCode::PayloadTooLarge_413: return "Payload Too Large";
  case HttpStatusCode::UriTooLong_414: return "URI Too Long";
  case HttpStatusCode::UnsupportedMediaType_415: return "Unsupported Media Type";
  case HttpStatusCode::RangeNotSatisfiable_416: return "Range Not Satisfiable";
  case HttpStatusCode::ExpectationFailed_417: return "Expectation Failed";
  case HttpStatusCode::ImATeapot_418: return "I'm a teapot";
  case HttpStatusCode::MisdirectedRequest_421: return "Misdirected Request";
  case HttpStatusCode::UnprocessableContent_422: return "Unprocessable Content";
  case HttpStatusCode::Locked_423: return "Locked";
  case HttpStatusCode::FailedDependency_424: return "Failed Dependency";
  case HttpStatusCode::TooEarly_425: return "Too Early";
  case HttpStatusCode::UpgradeRequired_426: return "Upgrade Required";
  case HttpStatusCode::PreconditionRequired_428: return "Precondition Required";
  case HttpStatusCode::TooManyRequests_429: return "Too Many Requests";
  case HttpStatusCode::RequestHeaderFieldsTooLarge_431:
    return "Request Header Fields Too Large";
  case HttpStatusCode::UnavailableForLegalReasons_451:
    return "Unavailable For Legal Reasons";
  case HttpStatusCode::NotImplemented_501: return "Not Implemented";
  case HttpStatusCode::BadGateway_502: return "Bad Gateway";
  case HttpStatusCode::ServiceUnavailable_503: return "Service Unavailable";
  case HttpStatusCode::GatewayTimeout_504: return "Gateway Timeout";
  case HttpStatusCode::HttpVersionNotSupported_505:
    return "HTTP Version Not Supported";
  case HttpStatusCode::VariantAlsoNegotiates_506: return "Variant Also Negotiates";
  case HttpStatusCode::InsufficientStorage_507: return "Insufficient Storage";
  case HttpStatusCode::LoopDetected_508: return "Loop Detected";
  case HttpStatusCode::NotExtended_510: return "Not Extended";
  case HttpStatusCode::NetworkAuthenticationRequired_511:
    return "Network Authentication Required";

  default:
  case HttpStatusCode::InternalServerError_500: return "Internal Server Error";
  }
}


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

    /**
     * @brief Request URL params
     * 
     */
    std::array<std::uint32_t, HTTP_REQUEST_PARAM_COUNT> params { 0 };
};

/**
 * @brief A class that contains attributes of a single HTTP response
 * 
 */
template <class Server_t>
class HttpResponse : public std::ostream {
public:
    /**
     * @brief HTTP Response Headers
     * 
     */
    HttpHeaders headers;

    HttpResponse(Server_t& server, typename Server_t::Connection& connection) 
        : std::ostream(&m_osWrapper)
        , m_server(server)
        , m_connection(connection)
    {
    }

    /**
     * @brief Sets the status code of this response
     * 
     * @param status the new status code
     * @return a reference to self
     */
    HttpResponse& status(int status)
    {
        m_status = static_cast<HttpStatusCode>(status);
        return *this;
    }

    /**
     * @brief Sets the status code of this response
     * 
     * @param status the new status code
     * @return a reference to self
     */
    HttpResponse& status(HttpStatusCode status)
    {
        m_status = status;
        return *this;
    }

    /**
     * @brief Checks, if HTTP Response Headers have already been sent
     *        and can be no longer modified.
     * 
     * @return true, if headers have been sent,
     * @return false otherwise
     */
    bool headersSent() const
    {
        return m_headersSent;
    }

    /**
     * @brief Forces HTTP Response Headers to be sent immediately
     * 
     */
    void sendHeaders();

    /**
     * @brief Immediately sends entire buffer contents to underlying socket
     *        implementation
     * 
     */
    void flush();

    /**
     * @brief Sends a chunk of data directly to underlying socket implementation,
     *        skipping unnecessary memory copying
     *
     * This function is meant to be fast, so it does not check if HTTP headers
     * have already been sent. You must ensure that this is a case by calling
     * `sendHeaders()` before.
     *
     * You also shouldn't mix sendChunk calls with ostream operations. If that
     * has happened, be sure to call flush() before sendChunk() to ensure buffer
     * synchronization.
     *
     * Consider calling sendChunked() for larger portions of data.
     * 
     * @param data a pointer to data to transfer
     * @param size number of bytes to send
     */
    void sendChunk(const char* data, std::size_t size);


    /**
     * @brief Sends a portion of data directly to underlying socket 
     *        implementation, chunking it into smaller parts, skipping
     *        unnecessary memory copying
     *
     * This implementation is meant for large portions of data. For smaller ones,
     * you can call sendChunk().
     *
     * See sendChunk() for all precautions that also apply to this function.
     * 
     * @param data a pointer to data to transfer
     * @param size number of bytes to send
     */
    void sendChunked(const char* data, std::size_t size);

private:
    class OstreamWrapper : public std::streambuf
    {
    public:
        OstreamWrapper(HttpResponse& res)
            : m_res(res)
        {
        }

        int_type overflow(int_type ch) override
        {
            if (!m_res.m_headersSent) {
                m_res.sendHeaders();
            }

            m_res.m_buffer += ch;
            
            if (m_res.m_buffer.GetSize() > m_res.m_buffer.GetCapacity()) {
                m_res.flush();
            }

            return true;
        }

    private:
        HttpResponse& m_res;
    };

    Server_t& m_server;
    typename Server_t::Connection& m_connection;

    HttpStatusCode m_status { HttpStatusCode::OK_200 };
    bool m_headersSent { false };
    StaticString<HTTP_TX_CHUNK_SIZE> m_buffer;
    OstreamWrapper m_osWrapper { *this };
    std::ostream m_os { &m_osWrapper };
};

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
class HttpServer : public HttpServerBase {
    friend class HttpResponse<HttpServer>;

public:
    using Request = HttpRequest;
    using Response = HttpResponse<HttpServer>;
    using RequestHandler = std::function<void(Request&, Response&)>;

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

    /**
     * @brief Register a new request handler for all available HTTP methods
     * 
     * @param route route to handle
     * @param handler a handler that processes HttpRequest and produces HttpResponse
     */
    void all(const char* route, RequestHandler handler)
    {
        registerHandler(HttpMethod::GET, route, handler);
        registerHandler(HttpMethod::POST, route, handler);
        registerHandler(HttpMethod::PUT, route, handler);
        registerHandler(HttpMethod::PATCH, route, handler);
        registerHandler(HttpMethod::DELETE, route, handler);
    }

    /**
     * @brief Get underlying socket implementation instance
     * 
     * @return reference to underlying socket implementation
     */
    SocketImpl_t& getSocket() { return m_socketImpl; }

    /**
     * @brief Get underlying socket implementation instance
     * 
     * @return const reference to underlying socket implementation
     */
    const SocketImpl_t& getSocket() const { return m_socketImpl; }

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
        std::size_t sendBytes(const char* data, std::size_t numBytes);
        void flush();

    private:
        enum class ConnectionState {
            URI_AND_METHOD,
            REQUEST_HEADERS,
            REQUEST_BODY,
            RESPONSE,
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

        void processRequestLine();
        void handleRequest();
    };

    struct NoneURLPart {};

    struct NormalURLPart {
        std::string match;
    };

    struct ParamURLPart {
        std::uint32_t paramId;
    };

    struct AnyURLPart {};

    using URLPart = std::variant<
        NoneURLPart, NormalURLPart, ParamURLPart, AnyURLPart>;

    struct InternalHandler {
        RequestHandler handler;
        StaticVector<URLPart, HTTP_MAX_URL_PARTS> matcher;

        template <typename It>
        bool matches(It begin, It end);
    };

    SocketImpl_t m_socketImpl;
    std::array<Connection, MAX_CONNECTIONS> m_connections;
    std::array<std::vector<InternalHandler>, 
        static_cast<std::size_t>(HttpMethod::METHOD_COUNT)> m_handlers;

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
    // Register a final handler that matches all unprocessed requests
    // and returns 404 Not Found

    all("/*", [&](Request& req, Response& res) {
        res.status(HttpStatusCode::NotFound_404);
    });

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
    InternalHandler internalHandler = { std::move(handler) };
    
    while (*route) {
        char c = *route;

        if (c == '/') {
            // Skip any forward slashes
            ++route;
            continue;
        }

        if (c == '*') {
            while (*route && *route != '/') { 
                ++route;
            }

            internalHandler.matcher.Append(AnyURLPart {});
            continue;
        }

        if (c == ':') {
            StaticString<16> buffer;
            ++route;

            while (*route && *route != '/') { 
                buffer += *route;
                ++route;
            }

            internalHandler.matcher.Append(
                ParamURLPart { buffer.ToInteger<std::uint32_t>() });
            continue;
        }

        std::string urlPart;
        while (*route && *route != '/') {
            urlPart += *route;
            ++route;
        }

        internalHandler.matcher.Append( 
            NormalURLPart { std::move(urlPart) });
    }
    
    m_handlers.at(static_cast<int>(method)).emplace_back(std::move(internalHandler));
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
    m_buffer.Clear();
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
                    processRequestLine();
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
                m_state = ConnectionState::RESPONSE;
                handleRequest();
                
                flush();
                m_server->m_socketImpl.close(m_connectionId);
                m_state = ConnectionState::FINISHED;
            }
        }
    }
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
std::size_t HttpServer<SocketImpl_t, MAX_CONNECTIONS>::Connection::sendBytes(
    const char* data, std::size_t numBytes)
{
    return m_server->m_socketImpl.send(m_connectionId, data, numBytes);
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::Connection::flush()
{
    m_server->m_socketImpl.finish(m_connectionId);
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::Connection::processRequestLine()
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
        } else if (m_requestHeaders[m_requestHeaders.size() - 1].first 
            == STR("content-length")) {

            m_contentLength = m_requestHeaders[
                m_requestHeaders.size() - 1].second.ToInteger<std::size_t>();
        }
        break;
    default:
        break;
    }
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
void HttpServer<SocketImpl_t, MAX_CONNECTIONS>::Connection::handleRequest()
{
#ifdef HTTP_DEBUG
    std::cout << "Conn" << m_connectionId
              << ": "  << m_requestUrl.ToCStr() << std::endl;
#endif
    StaticVector<StaticString<64>, 8> urlParts;
    for (size_t pos = 0; pos < m_requestUrl.GetSize(); ++pos) {
        char c = m_requestUrl[pos];

        if (c == '/') {
            if (urlParts.IsEmpty() || !urlParts[urlParts.GetSize() - 1].IsEmpty()) {
                // Ignore multiple adjacent slashes
                urlParts.Append(StaticString<64>());
            }
        } else if (!urlParts.IsEmpty()) {
            urlParts[urlParts.GetSize() - 1] += c;
        }
    }

    if (!urlParts.IsEmpty() && urlParts[urlParts.GetSize() - 1].IsEmpty()) {
        urlParts.RemoveIndex(urlParts.GetSize() - 1);
    }

    for (auto& handler : m_server->m_handlers[static_cast<int>(m_requestMethod)])
    {
        if (handler.matches(urlParts.begin(), urlParts.end())) {
            Request req { 
                m_requestMethod, m_requestUrl, m_requestHeaders, m_buffer };
            
            int i = 0;
            for (auto& matcherPart : handler.matcher) {
                ParamURLPart* paramPart = std::get_if<ParamURLPart>(&matcherPart);
                if (paramPart) {
                    req.params[paramPart->paramId] = urlParts[i].ToInteger<int>();
                }
                ++i;
            }

            Response res(*m_server, *this);
            res.headers["Connection"] = "close";
            res.headers["Server"] = "microhttp";

            handler.handler(req, res);

            res.sendHeaders();
            res.flush();
            return;
        }
    }

    // None of the handlers matched the request
    // This should never happen

    m_server->m_socketImpl.close(m_connectionId);
    discard();
}

template <std::size_t maxSize>
static inline bool compareStrings(
    const std::string& s1, const StaticString<maxSize>& s2)
{
    if (s1.size() != s2.GetSize()) return false;
    auto it1 = s1.begin();
    auto it2 = s2.begin();

    while (it1 != s1.end() && it2 != s2.end()) {
        if (*it1 != *it2) return false;
        ++it1;
        ++it2;
    }

    return true;
}

template <SocketImpl SocketImpl_t, std::size_t MAX_CONNECTIONS>
template <typename It>
bool HttpServer<SocketImpl_t, MAX_CONNECTIONS>::InternalHandler::matches(
    It begin, It end)
{
    int i = 0;
    for (auto it = begin; !(it == end); ++it) {
        auto& urlPart = *it;

        if (i >= matcher.GetSize()) {
            return false;
        }

        auto nonePart = std::get_if<NoneURLPart>(&matcher[i]);
        auto normalPart = std::get_if<NormalURLPart>(&matcher[i]);
        auto paramPart = std::get_if<ParamURLPart>(&matcher[i]);
        auto anyPart = std::get_if<AnyURLPart>(&matcher[i]);

        if (nonePart) {
            return false;
        } else if (normalPart) {
            if (!compareStrings(normalPart->match, urlPart)) {
                return false;
            }
        } else if (paramPart) {
            // Intentionally do nothing
        } else if (anyPart) {
            return true;
        }
        

        ++i;
    }

    // Edge case: any matcher for empty URL
    if (!matcher.IsEmpty() && std::get_if<AnyURLPart>(&matcher[0])) {
        return true;
    }

    return i == matcher.GetSize();
}

template <class Server_t>
void HttpResponse<Server_t>::sendHeaders()
{
    if (m_headersSent) {
        return;
    }

    m_headersSent = true;

    static const char* CRLF = "\r\n";

    *this << "HTTP/1.1 " << static_cast<int>(m_status) 
          << ' ' << getHttpStatusMessage(m_status) << CRLF;

    for (const auto& header : headers)
    {
        *this << header.first << ": " << header.second << CRLF;
    }

    *this << CRLF;
}

template <class Server_t>
void HttpResponse<Server_t>::flush()
{
    std::size_t sent = m_connection.sendBytes(m_buffer.begin(), m_buffer.GetSize());

    if (sent == m_buffer.GetSize()) {
        m_buffer.Clear();
    } else {
        m_buffer.Skip(sent);
    }
}

template <class Server_t>
void HttpResponse<Server_t>::sendChunk(const char* data, std::size_t numBytes)
{
    while (numBytes) {
        std::size_t sent = m_connection.sendBytes(data, numBytes);

        if (sent == 0) {
            return;
        }

        data += sent;
        numBytes -= sent;
    }
}

template <class Server_t>
void HttpResponse<Server_t>::sendChunked(const char* data, std::size_t numBytes)
{
    while (numBytes) {
        std::size_t toSend = numBytes;
        if (toSend > HTTP_TX_CHUNK_SIZE) {
            toSend = HTTP_TX_CHUNK_SIZE;
        }

        std::size_t sent = m_connection.sendBytes(data, numBytes);
        
        if (sent == 0) {
            return;
        }

        data += sent;
        numBytes -= sent;
    }
}

};
