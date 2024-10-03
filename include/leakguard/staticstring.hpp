#pragma once
#include <algorithm>
#include <array>
#include <cstdlib>

namespace lg {

/**
 * @brief A dynamically sized string class using only statically allocated memory.
 *
 * This class can store any number of characters, up to its capacity. Any extra
 * characters will be dropped during its internal operations.
 *
 * StaticString will never throw any exceptions.
 *
 * @tparam maxSize String capacity, in characters
 */
template <std::size_t maxSize>
class StaticString {
public:
    static_assert(maxSize > 0, "string capacity must be greater than 0");

    template <std::size_t otherSize>
    friend class StaticString;

    /**
     * @brief Bidirectional, random access iterator to characters
     */
    using Iterator = char*;

    /**
     * @brief Bidirectional, random access const iterator to characters
     */
    using ConstIterator = const char*;

    /**
     * @brief Converts an integral value to string.
     *
     * Ensure that string capacity is large enough. If the value does not fit,
     * an empty string will be returned.
     *
     * @tparam T integer type
     * @param value value to convert
     * @return newly constructed string
     */
    template <typename T>
    static StaticString Of(T value)
    {
        // NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
        static constexpr char DIGITS[] = "0001020304050607080910111213141516171819"
                                         "2021222324252627282930313233343536373839"
                                         "4041424344454647484950515253545556575859"
                                         "6061626364656667686970717273747576777879"
                                         "8081828384858687888990919293949596979899";
        // NOLINTEND(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)

        using UT = std::make_unsigned_t<T>;

        bool negative = value < 0;
        UT absolute = static_cast<UT>(negative ? (-value) : value);

        size_t outputLength = negative ? 1 : 0;
        UT absoluteCopy = absolute;

        static constexpr unsigned int BASE = 10;
        static constexpr unsigned int BASE_2 = 100;
        static constexpr unsigned int BASE_3 = 1000;
        static constexpr unsigned int BASE_4 = 10000;

        while (true) {
            if (absoluteCopy < BASE) {
                outputLength += 1;
                break;
            } else if (absoluteCopy < BASE_2) {
                outputLength += 2;
                break;
            } else if (absoluteCopy < BASE_3) {
                outputLength += 3;
                break;
            } else if (absoluteCopy < BASE_4) {
                outputLength += 4;
                break;
            }

            outputLength += 4;
            absoluteCopy /= BASE_4;
        }

        StaticString result;

        if (outputLength <= maxSize) {
            result.m_currentSize = outputLength;

            size_t bufferPosition = outputLength - 1;

            if (negative) {
                result.m_buffer[0] = '-';
            }

            while (absolute >= BASE_2) {
                UT part = absolute % BASE_2;
                result.m_buffer[bufferPosition--] = DIGITS[part * 2 + 1];
                result.m_buffer[bufferPosition--] = DIGITS[part * 2];

                absolute /= BASE_2;
            }

            if (absolute >= BASE) {
                result.m_buffer[bufferPosition--] = DIGITS[absolute * 2 + 1];
                result.m_buffer[bufferPosition] = DIGITS[absolute * 2];
            } else {
                result.m_buffer[bufferPosition] = DIGITS[absolute * 2 + 1];
            }

            result.m_buffer[result.m_currentSize] = '\0';
        }

        return result;
    }

    /**
     * @name Constructors and destructors
     */
    ///@{

    /**
     * @brief Default constructor, creates an empty string
     */
    constexpr StaticString() noexcept
        : m_buffer({})
    {
        m_buffer[0] = '\0';
    }

    /**
     * @brief Default destructor
     */
    ~StaticString() = default;

    /**
     * @brief Copy constructor, copies contents of another StaticString instance.
     *
     * @tparam otherSize capacity of the second string
     * @param other string to copy contents from
     */
    template <std::size_t otherSize>
    constexpr StaticString(const StaticString<otherSize>& other) noexcept
    {
        *this = other;
    }

    /**
     * @brief Copy constructor, copies contents of another StaticString instance.
     *
     * @param other string to copy contents from
     */
    constexpr StaticString(const StaticString& other) noexcept
    {
        *this = other;
    }

    /**
     * @brief Move constructor, copies contents of another StaticString instance.
     *
     * It performs exactly the same as a copy constructor.
     *
     * @param other string to copy contents from
     */
    constexpr StaticString(StaticString&& other)
        : StaticString(other)
    {
    }

    /**
     * @brief Constructs a StaticString instance from zero-terminated C-style char array
     *
     * @param buffer pointer to a zero-terminated char array
     */
    constexpr StaticString(const char* buffer) noexcept
    {
        *this = buffer;
    }

    /**
     * @brief Construct a StaticString instance from char array and its length
     *
     * @param buffer pointer to char array
     * @param length number of characters
     */
    constexpr StaticString(const char* buffer, size_t length) noexcept
    {
        // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        m_currentSize = std::min(maxSize, length);
        std::copy(buffer, buffer + m_currentSize, m_buffer.begin());
        // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

        m_buffer[m_currentSize] = '\0';
    }
    ///@}

    /**
     * @name Operators
     */
    ///@{

    /**
     * @brief Assignment operator, copies contents of another string
     *
     * @tparam otherSize capacity of the second string
     * @param other the instance of the second string
     * @return reference to self
     */
    template <std::size_t otherSize>
    constexpr StaticString& operator=(const StaticString<otherSize>& other) noexcept
    {
        m_currentSize = std::min(maxSize, other.m_currentSize);
        std::copy(other.m_buffer.begin(),
            other.m_buffer.begin() + m_currentSize, m_buffer.begin());

        m_buffer[m_currentSize] = '\0';
        return *this;
    }

    /**
     * @brief Assignment operator, copies contents of another string
     *
     * @param other the instance of the second string
     * @return reference to self
     */
    constexpr StaticString& operator=(const StaticString& other) noexcept
    {
        std::copy(other.m_buffer.begin(),
            other.m_buffer.begin() + other.m_currentSize, m_buffer.begin());
        m_currentSize = other.m_currentSize;

        m_buffer[m_currentSize] = '\0';
        return *this;
    }

    /**
     * @brief Assignment operator, copies contents of zero-terminated C-style array
     *
     * @param buffer pointer to a zero-terminated char array
     * @return reference to self
     */
    constexpr StaticString& operator=(const char* buffer) noexcept
    {
        // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        for (m_currentSize = 0; m_currentSize < maxSize; ++m_currentSize) {
            m_buffer[m_currentSize] = buffer[m_currentSize];

            if (!m_buffer[m_currentSize])
                break;
        }

        m_buffer[m_currentSize] = '\0';
        return *this;
        // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    /**
     * @brief Move assignment operator, copies contents of another string
     *
     * It performs exactly the same as a normal copy assignment operator.
     *
     * @param other the instance of the second string
     * @return reference to self
     */
    constexpr StaticString& operator=(StaticString&& other)
    {
        *this = other;
        return *this;
    }

    /**
     * @brief Access n-th character of the string.
     *
     * In DEBUG mode additional bound checks are performed.
     *
     * @param n which character to access, indexing starts at 0
     * @return char& reference to char
     */
    char& operator[](size_t n) noexcept
    {
#ifdef NDEBUG
        if (n >= m_currentSize) {
            std::abort();
        }
#endif
        return m_buffer[n];
    }

    /**
     * @brief Access n-th character of the string.
     *
     * In DEBUG mode additional bound checks are performed.
     *
     * @param n which character to access, indexing starts at 0
     * @return char& reference to char
     */
    const char& operator[](size_t n) const noexcept
    {
#ifdef NDEBUG
        if (n >= m_currentSize) {
            std::abort();
        }
#endif
        return m_buffer[n];
    }

    /**
     * @brief Compares two string instances for equality
     *
     * @tparam otherSize capacity of the second string
     * @param other the second string to compare
     * @return true, if string contents match,
     * @return false otherwise
     */
    template <size_t otherSize>
    bool operator==(const StaticString<otherSize>& other) const noexcept
    {
        if (m_currentSize != other.m_currentSize) {
            return false;
        }

        for (size_t i = 0; i < m_currentSize; ++i) {
            if (m_buffer[i] != other.m_buffer[i])
                return false;
        }

        return true;
    }

    /**
     * @brief Compares two string instances for inequality
     *
     * @tparam otherSize capacity of the second string
     * @param other the second string to compare
     * @return true, if string contents don't match,
     * @return false otherwise
     */
    template <size_t otherSize>
    bool operator!=(const StaticString<otherSize>& other) const noexcept
    {
        return !(*this == other);
    }

    /**
     * @brief Appends (concatenates) a second string
     *
     * @tparam otherSize capacity of the second string
     * @param other string instance to append
     * @return reference to self
     */
    template <size_t otherSize>
    StaticString& operator+=(const StaticString<otherSize>& other) noexcept
    {
        size_t maxCharacters = maxSize - m_currentSize;
        size_t copyCharacters = std::min(maxCharacters, other.m_currentSize);

        std::copy(other.m_buffer.begin(),
            other.m_buffer.begin() + copyCharacters,
            m_buffer.begin() + m_currentSize);

        m_currentSize += copyCharacters;
        m_buffer[m_currentSize] = '\0';
        return *this;
    }

    /**
     * @brief Appends (concatenates) a zero-terminated C-style char array
     *
     * @param buffer pointer to a zero-terminated char array
     * @return reference to self
     */
    StaticString& operator+=(const char* buffer) noexcept
    {
        size_t maxCharacters = maxSize - m_currentSize;
        for (size_t i = 0; i < maxCharacters; ++i, ++m_currentSize) {
            // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            if (!buffer[i])
                break;
            m_buffer[m_currentSize] = buffer[i];
            // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        }

        m_buffer[m_currentSize] = '\0';
        return *this;
    }

    /**
     * @brief Appends a single character to string
     *
     * @param c character to append
     * @return reference to self
     */
    StaticString& operator+=(char c) noexcept
    {
        if (m_currentSize < maxSize) {
            m_buffer[m_currentSize++] = c;
            m_buffer[m_currentSize] = '\0';
        }

        return *this;
    }

    ///@}

    /**
     * @name Size getters
     */
    ///@{

    /**
     * @brief Gets the string capacity, which is its maximum length
     *
     * @return String capacity, in bytes/characters
     */
    [[nodiscard]] constexpr size_t GetCapacity() const noexcept
    {
        return maxSize;
    }

    /**
     * @brief Gets current length of the stored content
     *
     * @return String length, in bytes/characters
     */
    [[nodiscard]] size_t GetSize() const noexcept
    {
        return m_currentSize;
    }

    /**
     * @brief Gets current length of the stored content
     *
     * @return String length, in bytes/characters
     */
    [[nodiscard]] size_t GetLength() const noexcept
    {
        return m_currentSize;
    }

    /**
     * @brief Checks, if the string is currently empty
     *
     * @return true if it is empty,
     * @return false otherwise
     */
    [[nodiscard]] bool IsEmpty() const noexcept
    {
        return m_currentSize == 0;
    }

    ///@}

    /**
     * @name Conversions
     */
    ///@{

    /**
     * @brief Converts string to a C-style array of chars
     *
     * @return Pointer to a zero-terminated char array
     */
    [[nodiscard]] const char* ToCStr() const noexcept
    {
        return m_buffer.data();
    }

    /**
     * @brief Provides implicit conversion to a C-style array of chars
     *
     * @return Pointer to a zero-terminated char array
     */
    operator const char*() const noexcept
    {
        return m_buffer.data();
    }

    ///@}

    /**
     * @name Operations
     */
    ///@{

    /**
     * @brief Clears string contents
     */
    void Clear() noexcept
    {
        m_currentSize = 0;
        m_buffer[0] = '\0';
    }

    /**
     * @brief Checks, if this strings starts with the provided characters
     *
     * @tparam otherSize capacity of the second string
     * @param other string to check against
     * @return true, if the provided string is the prefix,
     * @return false otherwise
     */
    template <size_t otherSize>
    bool StartsWith(const StaticString<otherSize>& other) const noexcept
    {
        if (other.m_currentSize > m_currentSize) {
            return false;
        }

        for (size_t i = 0; i < other.m_currentSize; ++i) {
            if (m_buffer[i] != other.m_buffer[i])
                return false;
        }

        return true;
    }

    /**
     * @brief Checks, if this strings ends with the provided characters
     *
     * @tparam otherSize capacity of the second string
     * @param other string to check against
     * @return true, if the provided string is the suffix,
     * @return false otherwise
     */
    template <size_t otherSize>
    bool EndsWith(const StaticString<otherSize>& other) const noexcept
    {
        if (other.m_currentSize > m_currentSize) {
            return false;
        }

        for (int i = m_currentSize - 1, j = other.m_currentSize - 1; j >= 0; --i, --j) {
            if (m_buffer[i] != other.m_buffer[j])
                return false;
        }

        return true;
    }

    /**
     * @brief Returns an iterator to the beginning
     *
     * @return iterator object
     */
    [[nodiscard]] Iterator begin() noexcept
    {
        return m_buffer.begin();
    }

    /**
     * @brief Returns a const iterator to the beginning
     *
     * @return iterator object
     */
    [[nodiscard]] ConstIterator begin() const noexcept
    {
        return m_buffer.begin();
    }

    /**
     * @brief Returns an iterator to the end
     *
     * @return iterator object
     */
    [[nodiscard]] Iterator end() noexcept
    {
        return m_buffer.begin() + m_currentSize;
    }

    /**
     * @brief Returns a const iterator to the end
     *
     * @return iterator object
     */
    [[nodiscard]] ConstIterator end() const noexcept
    {
        return m_buffer.begin() + m_currentSize;
    }

    /**
     * @brief Truncates the string if its length exceeds the provided parameter
     *
     * @param length maximum length allowed
     *
     * @return true, if the string has been truncated,
     * @return false otherwise
     */
    bool Truncate(size_t length) noexcept
    {
        if (length >= m_currentSize) {
            return false;
        }

        m_currentSize = length;
        m_buffer[m_currentSize] = '\0';
        return true;
    }

    ///@}

private:
    size_t m_currentSize { 0 };
    std::array<char, maxSize + 1> m_buffer;
};

// NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)

/**
 * @brief A helper type that denotes a minimal capacity StaticString instance
 *        that is able to hold a literal of length `arrayLength`
 *
 * @tparam arrayLength length of the literal to be held
 */
template <size_t arrayLength>
using StaticStringOfLength = StaticString<std::max<size_t>(1, arrayLength - 1)>;

/**
 * @brief Constructs a StaticString instance from zero-terminated string literal
 *
 * This function will automatically deduce the minimal capacity of the created
 * string and thus should only be used for const instances.
 *
 * To create a StaticString instance with an arbitrary capacity,
 * see @ref StaticString constructors.
 *
 * @tparam arrayLength deduced literal length (with terminator character)
 * @param buffer reference to the literal
 * @return a StaticString instance with deduced capacity
 */
template <size_t arrayLength>
inline constexpr StaticStringOfLength<arrayLength> STR(const char (&buffer)[arrayLength])
{
    return StaticStringOfLength<arrayLength>(buffer, arrayLength - 1);
}

/**
 * @brief Constructs a StaticString instance from zero-terminated string literal
 *
 * This function will automatically deduce the minimal capacity of the created
 * string and thus should only be used for const instances.
 *
 * To create a StaticString instance with an arbitrary capacity,
 * see @ref StaticString constructors.
 *
 * @tparam arrayLength deduced literal length (with terminator character)
 * @param buffer reference to the literal
 * @return a StaticString instance with deduced capacity
 */
template <>
inline constexpr StaticStringOfLength<1> STR<1>(const char (&buffer)[1])
{
    return {};
}

// NOLINTEND(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)

};
