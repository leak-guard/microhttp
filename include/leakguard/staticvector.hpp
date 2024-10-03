#pragma once
#include <array>
#include <cstdlib>
#include <cstring>
#include <type_traits>
#include <utility>

namespace lg {

/**
 * @brief A dynamically sized array using only statically allocated memory.
 *
 * This class can store any elements of the provided type, up to its capacity.
 * Any extra elements will be dropped during its internal operations.
 *
 * StaticVector will never throw any exceptions.
 *
 * @tparam T the type of elements to be stored, should be default constructible
 * @tparam maxSize Vector capacity, in elements
 */
template <typename T, std::size_t maxSize>
class StaticVector {
public:
    static_assert(maxSize > 0, "vector capacity must be greater than 0");

    template <typename U, std::size_t otherSize>
    friend class StaticVector;

    /**
     * @brief Bidirectional, random access iterator to elements
     */
    using Iterator = T*;

    /**
     * @brief Bidirectional, random access const iterator to elements
     */
    using ConstIterator = const T*;

    /**
     * @name Constructors and destructors
     */
    ///@{

    /**
     * @brief Default constructor, initializes an empty vector
     */
    constexpr StaticVector() noexcept = default;

    /**
     * @brief Default destructor
     */
    ~StaticVector() = default;

    /**
     * @brief Copy constructor, copies contents of another StaticVector instance.
     *
     * @tparam U type of elements of the second vector
     * @tparam otherSize capacity of the second vector
     * @param other vector to copy contents from
     */
    template <typename U, std::size_t otherSize>
    constexpr StaticVector(const StaticVector<U, otherSize>& other) noexcept
    {
        *this = other;
    }

    /**
     * @brief Copy constructor, copies contents of another StaticVector instance.
     *
     * @param other vector to copy contents from
     */
    constexpr StaticVector(const StaticVector& other) noexcept
    {
        *this = other;
    }

    /**
     * @brief Move constructor, copies contents of another StaticVector instance.
     *
     * It performs exactly the same as a copy constructor.
     *
     * @param other vector to copy contents from
     */
    constexpr StaticVector(StaticVector&& other) noexcept
    {
        *this = other;
    }

    ///@}

    /**
     * @name Operators
     */
    ///@{

    /**
     * @brief Assignment operator, copies contents of another vector
     *
     * @tparam U type of elements of the second vector
     * @tparam otherSize capacity of the second vector
     * @param other the instance of the second vector
     * @return reference to self
     */
    template <typename U, std::size_t otherSize>
    constexpr StaticVector& operator=(const StaticVector<U, otherSize>& other) noexcept
    {
        m_currentSize = std::min(maxSize, other.m_currentSize);
        std::copy(other.m_buffer.begin(),
            other.m_buffer.begin() + m_currentSize, m_buffer.begin());

        return *this;
    }

    /**
     * @brief Assignment operator, copies contents of another vector
     *
     * @param other the instance of the second vector
     * @return reference to self
     */
    constexpr StaticVector& operator=(const StaticVector& other) noexcept
    {
        std::copy(other.m_buffer.begin(),
            other.m_buffer.begin() + other.m_currentSize, m_buffer.begin());
        m_currentSize = other.m_currentSize;

        return *this;
    }

    /**
     * @brief Move assignment operator, copies contents of another vector
     *
     * It performs exactly the same as a copy constructor.
     *
     * @param other the instance of the second vector
     * @return reference to self
     */
    constexpr StaticVector& operator=(StaticVector&& other) noexcept
    {
        *this = other;
        return *this;
    }

    /**
     * @brief Access n-th character of the vector.
     *
     * In DEBUG mode additional bound checks are performed.
     *
     * @param n which element to access, indexing starts at 0
     * @return reference to element
     */
    T& operator[](size_t n) noexcept
    {
#ifdef NDEBUG
        if (n >= m_currentSize) {
            std::abort();
        }
#endif
        return m_buffer[n];
    }

    /**
     * @brief Access n-th character of the vector.
     *
     * In DEBUG mode additional bound checks are performed.
     *
     * @param n which element to access, indexing starts at 0
     * @return const reference to element
     */
    const T& operator[](size_t n) const noexcept
    {
#ifdef NDEBUG
        if (n >= m_currentSize) {
            std::abort();
        }
#endif
        return m_buffer[n];
    }

    ///@}

    /**
     * @name Size getters
     */
    ///@{

    /**
     * @brief Gets the vector capacity, in number of elements
     *
     * @return capacity in number of elements
     */
    [[nodiscard]] constexpr size_t GetCapacity() const noexcept
    {
        return maxSize;
    }

    /**
     * @brief Gets the vector capacity, in bytes
     *
     * @return capacity in bytes
     */
    [[nodiscard]] constexpr size_t GetCapacityBytes() const noexcept
    {
        return maxSize * sizeof(T);
    }

    /**
     * @brief Gets the count of elements currently stored in the vector
     *
     * @return elements count
     */
    [[nodiscard]] size_t GetSize() const noexcept
    {
        return m_currentSize;
    }

    /**
     * @brief Checks, if the vector is currently empty
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
     * @name Operations
     */
    ///@{

    /**
     * @brief Gets pointer to vector data
     *
     * @return const pointer to vector data
     */
    [[nodiscard]] const T* GetDataPtr() const noexcept
    {
        return m_buffer.data();
    }

    /**
     * @brief Appends a single element to the vector
     *
     * @param element element to add
     * @return true, if the operation succeeded (vector wasn't full),
     * @return false otherwise
     */
    bool Append(const T& element) noexcept
    {
        if (m_currentSize < maxSize) {
            m_buffer[m_currentSize++] = element;
            return true;
        }

        return false;
    }

    /**
     * @brief Appends a single element to the vector using move semantics
     *
     * @param element element to add
     * @return true, if the operation succeeded (vector wasn't full),
     * @return false otherwise
     */
    bool Append(T&& element) noexcept
    {
        if (m_currentSize < maxSize) {
            m_buffer[m_currentSize++] = std::move(element);
            return true;
        }

        return false;
    }

    /**
     * @brief Clears the vector
     *
     */
    void Clear() noexcept
    {
        // If the class is trivially destructible, we can safely
        // assume that destructors needn't be called and clear operation can
        // be sped up.

        ClearInternal(std::is_trivially_destructible<T> {});
        m_currentSize = 0;
    }

    /**
     * @brief Removes an item specified by its index
     *
     * @param index index of the element to be removed
     * @return true, if the operation succeeded (index was in a valid range),
     * @return false otherwise
     */
    bool RemoveIndex(size_t index)
    {
        if (index >= m_currentSize)
            return false;

        m_buffer[index] = T {};
        --m_currentSize;

        for (size_t i = index; i < m_currentSize; ++i) {
            std::swap(m_buffer[i], m_buffer[i + 1]);
        }

        return true;
    }

    /**
     * @brief Removes all value occurences from the vector
     *
     * @param value value to be removed
     * @return number of removed elements
     */
    size_t RemoveValue(const T& value)
    {
        size_t removed = 0;

        size_t write_ptr = 0;

        for (size_t read_ptr = 0; read_ptr < m_currentSize; ++read_ptr) {
            if (m_buffer[read_ptr] == value) {
                m_buffer[read_ptr] = T {};
                ++removed;
            } else {
                if (write_ptr != read_ptr) {
                    std::swap(m_buffer[read_ptr], m_buffer[write_ptr]);
                }
                ++write_ptr;
            }
        }

        m_currentSize -= removed;
        return removed;
    }

    /**
     * @brief Insert a new element at the specified index
     *
     * @param index index of the element **before** which a new element will be placed
     * @param value value to be inserted
     * @return true, if the operation succeeded,
     * @return false otherwise
     */
    bool Insert(size_t index, const T& value)
    {
        size_t rotateCount = m_currentSize - index;
        if (rotateCount > maxSize)
            rotateCount = 0;

        if (Append(value)) {
            InsertRotateLeft(rotateCount);
            return true;
        }

        return false;
    }

    /**
     * @brief Insert a new element at the specified index using move semantics
     *
     * @param index index of the element **before** which a new element will be placed
     * @param value value to be inserted
     * @return true, if the operation succeeded,
     * @return false otherwise
     */
    bool Insert(size_t index, T&& value)
    {
        size_t rotateCount = m_currentSize - index;
        if (rotateCount > maxSize)
            rotateCount = 0;

        if (Append(std::move(value))) {
            InsertRotateLeft(rotateCount);
            return true;
        }

        return false;
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

    ///@}

private:
    size_t m_currentSize { 0 };
    std::array<T, maxSize> m_buffer;

    void InsertRotateLeft(size_t times)
    {
        T* element1 = m_buffer.begin() + m_currentSize - 1;
        T* element2 = m_buffer.begin() + m_currentSize - 2;

        while (times--) {
            std::swap(*element1, *element2);
            --element1;
            --element2;
        }
    }

    void ClearInternal(std::true_type)
    {
    }

    void ClearInternal(std::false_type)
    {
        for (size_t i = 0; i < m_currentSize; ++i)
            m_buffer[i] = T {};
    }
};

};
