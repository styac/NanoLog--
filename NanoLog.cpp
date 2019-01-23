/*
Distributed under the MIT License (MIT)

    Copyright (c) 2016 Karthik Iyengar
    Copyright (c) 2019 Istvan Simon

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in the
Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "NanoLog.hpp"

#include <cstring>
#include <chrono>
#include <ctime>
#include <tuple>
#include <queue>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <c++/7/atomic>
#include <c++/7/array>
#include <time.h>
#include <errno.h>

// --------------------------------------------------------------------

namespace
{
    
inline std::thread::id this_thread_id() noexcept
{    
    static thread_local const std::thread::id id = std::this_thread::get_id();
    return id;
}

inline std::uint64_t timestamp_now() noexcept
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
}

inline void format_timestamp(std::ostream & os, std::uint64_t timestamp) noexcept
{
    constexpr std::uint32_t time2sec = 1000*1000*1000;
    char buffer[32];
    const std::time_t time_t = timestamp / time2sec;
    const std::uint32_t frac_time = timestamp % time2sec;
    const auto gmtime = std::gmtime(&time_t);
    // 012345678901234567890123456789
    // [2018-12-30 14:38:27.uuuuuuuuu]
    std::strftime(buffer, 22, "[%F %T.", gmtime);
    sprintf(&buffer[21],  "%09u]", frac_time);
    os << buffer;
}

template < typename T, typename Tuple >
struct TupleIndex;

template < typename T,typename ... Types >
struct TupleIndex < T, std::tuple < T, Types... > >
{
    static constexpr const std::size_t value = 0;
};

template < typename T, typename U, typename ... Types >
struct TupleIndex < T, std::tuple < U, Types... > >
{
    static constexpr const std::size_t value = 1 + TupleIndex < T, std::tuple < Types... > >::value;
};
    
} // anonymous namespace

// -----------------------------------------------

namespace nanolog
{
    
void LogControl::unlock_loglevel() 
{
    m_loglevel.store(static_cast<std::uint8_t>(LogLevel::NONE), std::memory_order_release );        
}
    
void set_logCategory(LogControl::value_type mask) noexcept
{
    LogControl::instance().setCategory(mask);
}

void add_logCategory(LogControl::value_type mask) noexcept
{
    LogControl::instance().addCategory(mask);
}

void sub_logCategory(LogControl::value_type mask) noexcept
{
    LogControl::instance().subCategory(mask);
}    

typedef std::tuple < NanoLogLine::truncated_t,
    char, 
    std::uint16_t, 
    std::uint32_t, 
    std::uint64_t, 
    std::int16_t, 
    std::int32_t, 
    std::int64_t, 
    float, 
    double, 
    NanoLogLine::string_literal_t, 
    char *,
    NanoLogLine::dumpbytes_t,
    void * > SupportedTypes;

inline char const * to_string(LogLevel loglevel) noexcept
{
    static const char *str[] = {
         " TRC ",
         " DBG ",
         " INF ",
         " WRN ",
         " ERR ",
         " CRT ",
         " IERROR ",
         " SKIPPED ",
    };

    const auto ll = std::uint8_t(loglevel);
    return ll < std::uint8_t(LogLevel::NONE) ? str[ll] : " XXX ";
}

template < typename Arg >
void NanoLogLine::encode(Arg arg) noexcept
{
    *reinterpret_cast<Arg*>(buffer()) = arg;
    m_bytes_used += sizeof(Arg);
}

template < typename Arg >
void NanoLogLine::encode(Arg arg, std::uint8_t type_id) noexcept
{
    if( resize_buffer_if_needed(sizeof(Arg) + sizeof(std::uint8_t)) )
    {        
        encode < std::uint8_t >(type_id);
        encode < Arg >(arg);
    }
    else // truncate
    {
        auto type_id = TupleIndex < truncated_t, SupportedTypes >::value;
        encode < std::uint8_t >(type_id);
    }
}

#ifdef NANOLOG_TRUNCATE_LONG_LINES

NanoLogLine::NanoLogLine(LogLevel level, char const * file, char const * function, std::uint32_t line, char const * category) noexcept
: m_timestamp(timestamp_now())
, m_file(file)
, m_function(function) 
, m_category(category) 
, m_thread_id(this_thread_id())
, m_line(line)
, m_bytes_used(0)
, m_loglevel(level)
{}

NanoLogLine::NanoLogLine() noexcept
: m_timestamp()
, m_file("")
, m_function("") 
, m_category("") 
, m_thread_id()
, m_line()
, m_bytes_used(0)
, m_loglevel(LogLevel::NONE)
{}

#else // NANOLOG_TRUNCATE_LONG_LINES

NanoLogLine::NanoLogLine(LogLevel level, char const * file, char const * function, std::uint32_t line, char const * category) noexcept
: m_bytes_used(0)
, m_buffer_size(sizeof(m_stack_buffer))
, m_heap_buffer()
, m_timestamp(timestamp_now())
, m_file(file)
, m_function(function) 
, m_category(category) 
, m_thread_id(this_thread_id())
, m_line(line)
, m_loglevel(level)
{}

NanoLogLine::NanoLogLine() noexcept
: m_bytes_used(0)
, m_buffer_size(sizeof(m_stack_buffer))
, m_heap_buffer()
, m_timestamp()
, m_file("")
, m_function("") 
, m_category("") 
, m_thread_id()
, m_line()
, m_loglevel(LogLevel::NONE)
{}

#endif // NANOLOG_TRUNCATE_LONG_LINES

void NanoLogLine::stringify(std::ostream & os) noexcept
{
#ifdef NANOLOG_TRUNCATE_LONG_LINES
    char * b = m_stack_buffer;
#else // NANOLOG_TRUNCATE_LONG_LINES
    char * b = !m_heap_buffer ? m_stack_buffer : m_heap_buffer.get();
#endif // NANOLOG_TRUNCATE_LONG_LINES
    char const * const end = b + m_bytes_used;
    auto format = LogControl::instance().get_logFormat();       
    os << std::dec;    
    if( format & std::uint8_t(LogFormat::LF_DATE_TIME) ) 
    {
        format_timestamp(os, m_timestamp);
    }    
    os << to_string(m_loglevel);
    if( m_category.m_s[0] != 0 ) {
        os << m_category.m_s << " ";        
    }
    if( format & std::uint8_t(LogFormat::LF_THREAD) ) 
    {
        auto flags = os.flags();
        os << std::hex << std::uppercase << m_thread_id << " ";
        os.flags(flags);
    }
    if( format & std::uint8_t(LogFormat::LF_FILE_FUNC) ) 
    {
        os << "[" << m_file.m_s
        << ':' << m_function.m_s
        << ':' << m_line << "] " ;
    }    
    stringify(os, b, end);
    os << "\n";
    if (m_loglevel >= LogLevel::CRIT)
        os.flush();
}

template < typename Arg >
char * decode(std::ostream & os, char * b, Arg * dummy) noexcept
{
    Arg arg = *reinterpret_cast < Arg * >(b);
    os << arg;
    return b + sizeof(Arg);
}

template <>
char * decode(std::ostream & os, char * b, NanoLogLine::string_literal_t * dummy) noexcept
{
    NanoLogLine::string_literal_t s = *reinterpret_cast < NanoLogLine::string_literal_t * >(b);
    os << s.m_s;
    return b + sizeof(NanoLogLine::string_literal_t);
}

// dump bytes in hex
template <>
char * decode(std::ostream & os, char * b, NanoLogLine::dumpbytes_t * dummy) noexcept
{
    static char hexc[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };    
    std::uint8_t length = *b;
    for(auto i=0u; i<length; ++i)
    {
        std::uint8_t byte = *(++b);
        os << ' ' << (hexc[byte>>4]) << (hexc[byte&0x0F]);
    }          
    return ++b;
}

template <>
char * decode(std::ostream & os, char * b, NanoLogLine::truncated_t * dummy) noexcept
{
    os << " <TRUNCATED>";
    return nullptr;
}

template <>
char * decode(std::ostream & os, char * b, char ** dummy) noexcept
{
    while (*b != '\0')
    {
        os << *b;
        ++b;
    }
    return ++b;
}

template <>
char * decode(std::ostream & os, char * b, void ** dummy) noexcept
{
    constexpr auto vpsize = sizeof(void *);    
    std::uint64_t arg = *reinterpret_cast < std::uint64_t * >(b);
    auto flags = os.flags();
    os << "0x" << std::setw(vpsize*2) << std::setfill('0') << std::hex << std::uppercase << arg;
    // os << ((void *)arg);
    os.flags(flags);
    return b + vpsize;
}

void NanoLogLine::encode_c_string(char const * arg, size_t length) noexcept
{
    if (length == 0)
        return;

    if( resize_buffer_if_needed(1 + length + 1) )
    {        
        char * b = buffer();
        auto type_id = TupleIndex < char *, SupportedTypes >::value;
        *reinterpret_cast<std::uint8_t*>(b++) = static_cast<std::uint8_t>(type_id);
        memcpy(b, arg, length + 1);
        m_bytes_used += 1 + length + 1;
    }
    else // truncate
    {
        char * b = buffer();
        int remaining_bytes = int(m_buffer_size) - int(m_bytes_used) - 4; // 2 token + \0
        if( remaining_bytes > 0 )
        {
            auto type_id = TupleIndex < char *, SupportedTypes >::value;
            *reinterpret_cast<std::uint8_t*>(b++) = static_cast<std::uint8_t>(type_id);
            length = std::min( int(length), remaining_bytes);
            memcpy(b, arg, length); 
            b += length;
            *b++ = 0;
            truncate(b);
        }
        else
        {
            truncate(b);
        }
    }
}

void NanoLogLine::encode(dumpbytes_t const& arg) noexcept
{    
    auto length = arg.size;
    if (length == 0)
        return;
    if(length>128)
    {
       length=128; 
    }
    
    if( resize_buffer_if_needed(1 + length + 1) )
    {
        char * b = buffer();
        auto type_id = TupleIndex < dumpbytes_t, SupportedTypes >::value;
        *reinterpret_cast<std::uint8_t*>(b++) = static_cast<std::uint8_t>(type_id);
        *reinterpret_cast<std::uint8_t*>(b++) = std::uint8_t(length);
        memcpy(b, arg.ptr, length);
        m_bytes_used += 2 + length;
    }
    else
    {        
        char * b = buffer();
        int remaining_bytes = int(m_buffer_size) - int(m_bytes_used) - 3; // 2 token + length
        if( remaining_bytes > 0 )
        {
            auto type_id = TupleIndex < dumpbytes_t, SupportedTypes >::value;
            *reinterpret_cast<std::uint8_t*>(b++) = static_cast<std::uint8_t>(type_id);
            length = std::min( int(length), remaining_bytes);
            *reinterpret_cast<std::uint8_t*>(b++) = std::uint8_t(length);
            memcpy(b, arg.ptr, length); 
            b += 2 + length;
            truncate(b);
        }
        else
        {
            truncate(b);
        }
    }
}

void NanoLogLine::stringify(std::ostream & os, char * start, char const * const end) const noexcept
{
    if ((start == nullptr) || (start == end))
        return;

    int type_id = static_cast < int >(*start); start++;

    switch (type_id)
    {
    case 1:
        stringify(os, decode(os, start, static_cast<std::tuple_element<1, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 2:
        stringify(os, decode(os, start, static_cast<std::tuple_element<2, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 3:
        stringify(os, decode(os, start, static_cast<std::tuple_element<3, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 4:
        stringify(os, decode(os, start, static_cast<std::tuple_element<4, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 5:
        stringify(os, decode(os, start, static_cast<std::tuple_element<5, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 6:
        stringify(os, decode(os, start, static_cast<std::tuple_element<6, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 7:
        stringify(os, decode(os, start, static_cast<std::tuple_element<7, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 8:
        stringify(os, decode(os, start, static_cast<std::tuple_element<8, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 9:
        stringify(os, decode(os, start, static_cast<std::tuple_element<9, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 10:
        stringify(os, decode(os, start, static_cast<std::tuple_element<10, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 11:
        stringify(os, decode(os, start, static_cast<std::tuple_element<11, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 12:
        stringify(os, decode(os, start, static_cast<std::tuple_element<12, SupportedTypes>::type*>(nullptr)), end);
        return;
    case 13:
        stringify(os, decode(os, start, static_cast<std::tuple_element<13, SupportedTypes>::type*>(nullptr)), end);
        return;
    default:
        // check potential corruption
        stringify(os, decode(os, start, static_cast<std::tuple_element<0, SupportedTypes>::type*>(nullptr)), end);
        return;
    }

    static_assert( 13 == ( std::tuple_size<SupportedTypes>::value - 1 ), "FATAL: not implemented type" );
}

#ifdef NANOLOG_TRUNCATE_LONG_LINES

void NanoLogLine::truncate(char * b) noexcept
{
    auto type_id = TupleIndex < truncated_t, SupportedTypes >::value;
    *b = type_id;
    m_bytes_used = m_buffer_size;
}

inline char * NanoLogLine::buffer() noexcept
{
    return &m_stack_buffer[m_bytes_used];
}

bool NanoLogLine::resize_buffer_if_needed(size_t additional_bytes) noexcept
{
    return m_bytes_used + additional_bytes < m_buffer_size; // save 1 byte
}

#else // NANOLOG_TRUNCATE_LONG_LINES

void NanoLogLine::truncate(char * b) noexcept
{
    auto type_id = TupleIndex < truncated_t, SupportedTypes >::value;
    *b = type_id;
    m_bytes_used = m_buffer_size;
    set_ierror();
}

inline char * NanoLogLine::buffer() noexcept
{
    return !m_heap_buffer ? &m_stack_buffer[m_bytes_used] : &(m_heap_buffer.get())[m_bytes_used];
}

bool NanoLogLine::resize_buffer_if_needed(size_t additional_bytes) noexcept
{
    size_t const required_size = m_bytes_used + additional_bytes;

    if (required_size < m_buffer_size) // save 1 byte for truncated
        return true;

    if (!m_heap_buffer)
    {
        try
        {
            m_buffer_size = std::max(static_cast<size_t>(512), required_size);
            m_heap_buffer.reset(new char[m_buffer_size]);            
            memcpy(m_heap_buffer.get(), m_stack_buffer, m_bytes_used);
            return true;
        }
        catch( ... )
        {
            return false;
        }
    }
    
    try
    {
        m_buffer_size = std::max(static_cast<size_t>(2 * m_buffer_size), required_size);
        std::unique_ptr < char [] > new_heap_buffer(new char[m_buffer_size]);            
        memcpy(new_heap_buffer.get(), m_heap_buffer.get(), m_bytes_used);
        m_heap_buffer.swap(new_heap_buffer);
        return true;
    }
    catch( ... )
    {
        return false;
    }
}

#endif // NANOLOG_TRUNCATE_LONG_LINES

void NanoLogLine::encode(char const * arg) noexcept
{
    if (arg != nullptr)
        encode_c_string(arg, std::strlen(arg));
}

void NanoLogLine::encode(char * arg) noexcept
{
    if (arg != nullptr)
        encode_c_string(arg, std::strlen(arg));
}

void NanoLogLine::encode(string_literal_t arg) noexcept
{
    encode < string_literal_t >(arg, TupleIndex < string_literal_t, SupportedTypes >::value);
}

NanoLogLine& NanoLogLine::operator<<(std::string const & arg) noexcept
{
    encode_c_string(arg.c_str(), arg.length());
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(std::int16_t arg) noexcept
{
    encode < std::int16_t >(arg, TupleIndex < std::int16_t, SupportedTypes >::value);
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(std::uint16_t arg) noexcept
{
    encode < std::uint16_t >(arg, TupleIndex < std::uint16_t, SupportedTypes >::value);
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(std::int32_t arg) noexcept
{
    encode < std::int32_t >(arg, TupleIndex < std::int32_t, SupportedTypes >::value);
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(std::uint32_t arg) noexcept
{
    encode < std::uint32_t >(arg, TupleIndex < std::uint32_t, SupportedTypes >::value);
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(std::int64_t arg) noexcept
{
    encode < std::int64_t >(arg, TupleIndex < std::int64_t, SupportedTypes >::value);
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(std::uint64_t arg) noexcept
{
    encode < std::uint64_t >(arg, TupleIndex < std::uint64_t, SupportedTypes >::value);
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(double arg) noexcept
{
    encode < double >(arg, TupleIndex < double, SupportedTypes >::value);
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(float arg) noexcept
{
    encode < float >(arg, TupleIndex < float, SupportedTypes >::value);
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(char arg) noexcept
{
    encode < char >(arg, TupleIndex < char, SupportedTypes >::value);
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(void * arg) noexcept
{
    encode < void * >(arg, TupleIndex < void *, SupportedTypes >::value);
    return *this;
}

NanoLogLine& NanoLogLine::operator<<(dumpbytes_t const & arg) noexcept
{
    encode(arg);
    return *this;
}

struct BufferBase
{
    virtual ~BufferBase() = default;
    virtual void push(NanoLogLine && logline) = 0;
    virtual bool try_pop(NanoLogLine & logline) = 0;
};

struct SpinLock final
{
    SpinLock(std::atomic_flag & flag) 
    : m_flag(flag)
    {
        while (m_flag.test_and_set(std::memory_order_acquire))
            ;
    }

    ~SpinLock()
    {
        m_flag.clear(std::memory_order_release);
    }

private:
    std::atomic_flag & m_flag;
};

/* Multi Producer Single Consumer Ring Buffer */
class RingBuffer final : public BufferBase
{
public:
    struct alignas(64) Item
    {
        Item()
        : flag{ ATOMIC_FLAG_INIT }
        , written(0)
        , logline()
        {}

        std::atomic_flag flag;
        char written;
        char padding[ LINEBUFFER_SIZE - sizeof(std::atomic_flag) - sizeof(char) - sizeof(NanoLogLine)];
        NanoLogLine logline;
    };

    RingBuffer(size_t const size)
        : m_size(size)
        , m_ring(static_cast<Item*>(std::malloc(size * sizeof(Item))))
        , m_write_index(0)
        , m_read_index(0)
    {
        for (size_t i = 0; i < m_size; ++i)
        {
            new (&m_ring[i]) Item();
        }
        static_assert(sizeof(Item) == LINEBUFFER_SIZE, "Unexpected size != BASE_LINE_BUFFER_SIZE");
    }

    ~RingBuffer()
    {
        for (size_t i = 0; i < m_size; ++i)
        {
            m_ring[i].~Item();
        }
        std::free(m_ring);
    }

    void push(NanoLogLine && logline) override
    {
        unsigned int write_index = m_write_index.fetch_add(1, std::memory_order_relaxed) % m_size;
        Item & item = m_ring[write_index];
        SpinLock spinlock(item.flag);
        if( ( item.written > 0 ) && (item.logline.get_loglevel() > logline.get_loglevel() ) ) 
        {
            // lower level should be dropped not overwrite !
            return;
        }
        item.logline = std::move(logline);
        ++item.written;
        if(item.written>100) {
           item.written=100; 
        }
    }

    bool try_pop(NanoLogLine & logline) override
    {
        Item & item = m_ring[m_read_index % m_size];
        SpinLock spinlock(item.flag);
        if (item.written > 0)
        {
            logline = std::move(item.logline);
            if(item.written > 1) 
            {
                logline.set_skipped();
            }
            item.written = 0;
            ++m_read_index;
            return true;
        }
        return false;
    }
    RingBuffer(RingBuffer const &) = delete;
    RingBuffer& operator=(RingBuffer const &) = delete;

private:
    size_t const m_size;
    Item * m_ring;
    std::atomic < unsigned int > m_write_index;
    char pad[ 64 - sizeof(m_size) - sizeof(m_ring) - sizeof(m_write_index) ];
    unsigned int m_read_index;
};

class Buffer final
{
public:
    struct Item
    {
        Item(NanoLogLine && nanologline)
        : logline(std::move(nanologline))
        {}
        char padding[ LINEBUFFER_SIZE - sizeof(NanoLogLine) ];
        NanoLogLine logline;
    };

    static constexpr const size_t size = 32768; // 8MB. Helps reduce memory fragmentation

    Buffer()
    : m_buffer(static_cast<Item*>(std::malloc(size * sizeof(Item))))
    {
        for (size_t i = 0; i <= size; ++i)
        {
            m_write_state[i].store(0, std::memory_order_relaxed);
        }
        static_assert(sizeof(Item) == LINEBUFFER_SIZE, "Unexpected size != BASE_LINE_BUFFER_SIZE");
    }

    ~Buffer()
    {
        unsigned int write_count = m_write_state[size].load();
        for (size_t i = 0; i < write_count; ++i)
        {
            m_buffer[i].~Item();
        }
        std::free(m_buffer);
    }

    // Returns true if we need to switch to next buffer
    bool push(NanoLogLine && logline, unsigned int const write_index)
    {
        new (&m_buffer[write_index]) Item(std::move(logline));
        m_write_state[write_index].store(1, std::memory_order_release);
        return m_write_state[size].fetch_add(1, std::memory_order_acquire) + 1 == size;
    }

    bool try_pop(NanoLogLine & logline, unsigned int const read_index)
    {
        if (m_write_state[read_index].load(std::memory_order_acquire))
        {
            Item & item = m_buffer[read_index];
            logline = std::move(item.logline);
            return true;
        }
        return false;
    }

    Buffer(Buffer const &) = delete;
    Buffer& operator=(Buffer const &) = delete;

private:
    Item * m_buffer;
    std::atomic < unsigned int > m_write_state[size + 1];
};

class QueueBuffer final : public BufferBase
{
public:
    QueueBuffer(QueueBuffer const &) = delete;
    QueueBuffer& operator=(QueueBuffer const &) = delete;
    QueueBuffer()
    : m_current_read_buffer{nullptr}
    , m_write_index(0)
    , m_flag{ATOMIC_FLAG_INIT}
    , m_read_index(0)
    {
        setup_next_write_buffer();
    }

    void push(NanoLogLine && logline) override
    {
        unsigned int write_index = m_write_index.fetch_add(1, std::memory_order_relaxed);
        if (write_index < Buffer::size)
        {
            if (m_current_write_buffer.load(std::memory_order_acquire)->push(std::move(logline), write_index))
            {
                setup_next_write_buffer();
            }
        }
        else
        {
            while (m_write_index.load(std::memory_order_acquire) >= Buffer::size);
            push(std::move(logline));
        }
    }

    bool try_pop(NanoLogLine & logline) override
    {
        if (m_current_read_buffer == nullptr)
            m_current_read_buffer = get_next_read_buffer();

        Buffer * read_buffer = m_current_read_buffer;

        if (read_buffer == nullptr)
            return false;

        if (read_buffer->try_pop(logline, m_read_index))
        {
            m_read_index++;
            if (m_read_index == Buffer::size)
            {
                m_read_index = 0;
                m_current_read_buffer = nullptr;
                SpinLock spinlock(m_flag);
                m_buffers.pop();
            }
            return true;
        }
        return false;
    }

private:
    void setup_next_write_buffer()
    {
        // TODO add error handling - exception + return val
        std::unique_ptr < Buffer > next_write_buffer(new Buffer());
        m_current_write_buffer.store(next_write_buffer.get(), std::memory_order_release);
        SpinLock spinlock(m_flag);
        m_buffers.push(std::move(next_write_buffer));
        m_write_index.store(0, std::memory_order_relaxed);
    }

    Buffer * get_next_read_buffer()
    {
        SpinLock spinlock(m_flag);
        return m_buffers.empty() ? nullptr : m_buffers.front().get();
    }

    std::queue < std::unique_ptr < Buffer > > m_buffers;
    std::atomic < Buffer * > m_current_write_buffer;
    Buffer * m_current_read_buffer;
    std::atomic < unsigned int > m_write_index;
    std::atomic_flag m_flag;
    unsigned int m_read_index;
};

class FileWriter final
{
public:
    FileWriter(std::string const & log_directory, std::string const & log_file_name, std::uint32_t log_file_roll_size_mb)
    : m_bytes_written(0)
    , m_log_file_roll_size_bytes(log_file_roll_size_mb * 1024 * 1024)
    , m_name(log_directory + log_file_name + "_")
    , m_os()
    , m_useFile(true)
    {
        if( log_file_name.size() == 0 )
        {
            m_useFile = false;
        }
        else
        {
            roll_file();
        }
    }

    ~FileWriter()
    {
        m_os.flush();
        m_os.close();        
    }
    
    void write(NanoLogLine & logline)
    {
        if( m_useFile )
        {
            auto pos = m_os.tellp();
            logline.stringify(m_os);
            m_bytes_written += m_os.tellp() - pos;
            if (m_bytes_written > m_log_file_roll_size_bytes)
            {
                roll_file();
            }
        }
        else
        {
            logline.stringify(std::cout);
        }
    }

private:
    void roll_file()
    {
        constexpr std::uint32_t time2sec = 1000*1000*1000;
        char buffer[40];
        m_os.flush();
        m_os.close();
        m_bytes_written = 0;
        auto filetime = timestamp_now();
        const std::time_t time_t = filetime / time2sec;
        const std::uint32_t frac_time = filetime % time2sec;
        const auto gmtime = std::gmtime(&time_t);
        std::strftime( buffer, 20, "%F_%T", gmtime );
        sprintf( &buffer[19], "_%09u.log", frac_time );
        m_os.open( m_name + buffer, std::ofstream::out | std::ofstream::trunc );
    }

    std::streamoff      m_bytes_written;
    std::uint32_t const m_log_file_roll_size_bytes;
    std::string const   m_name;
    std::ofstream       m_os;
    std::uint8_t        m_useFile : 1;
};

class NanoLogger final
{
public:
    NanoLogger(NonGuaranteedLogger ngl, std::string const & log_directory, std::string const & log_file_name, std::uint32_t log_file_roll_size_mb)
    : m_state(State::INIT)
    , m_buffer_base(new RingBuffer(std::max(1u, ngl.ring_buffer_size_mb) * 1024 * 4))
    , m_file_writer(log_directory, log_file_name, std::max(1u, log_file_roll_size_mb))
    , m_thread(&NanoLogger::pop, this)
    {
        m_state.store(State::READY, std::memory_order_release);
        LogControl::instance().unlock_loglevel(); // sets to NONE - hopefully nobody will change in the next microsec
    }

    NanoLogger(GuaranteedLogger gl, std::string const & log_directory, std::string const & log_file_name, std::uint32_t log_file_roll_size_mb)
    : m_state(State::INIT)
    , m_buffer_base(new QueueBuffer())
    , m_file_writer(log_directory, log_file_name, std::max(1u, log_file_roll_size_mb))
    , m_thread(&NanoLogger::pop, this)
    {
        m_state.store(State::READY, std::memory_order_release);
        LogControl::instance().unlock_loglevel(); // sets to NONE - hopefully nobody will change in the next microsec
    }

    ~NanoLogger()
    {
        m_state.store(State::SHUTDOWN);
        m_thread.join();
    }

    void add(NanoLogLine && logline)
    {
        m_buffer_base->push(std::move(logline));
    }

    void pop()
    {
        NanoLogLine logline;
        // Wait for constructor to complete and pull all stores done there to this thread / core.
        while (m_state.load(std::memory_order_acquire) == State::INIT)
            std::this_thread::sleep_for(std::chrono::microseconds(50));

        while (m_state.load() == State::READY)
        {
            if (m_buffer_base->try_pop(logline))
                m_file_writer.write(logline);
            else
              std::this_thread::sleep_for(std::chrono::microseconds(50));
        }

        // Pop and log all remaining entries
        while (m_buffer_base->try_pop(logline))
        {
            m_file_writer.write(logline);
        }
    }

private:
    enum class State
    {
        INIT,
        READY,
        SHUTDOWN
    };

    std::atomic < State > m_state;
    std::unique_ptr < BufferBase > m_buffer_base;
    FileWriter m_file_writer;
    std::thread m_thread;
};

std::unique_ptr < NanoLogger > nanologger;
std::atomic < NanoLogger * > atomic_nanologger;

bool NanoLog::operator==(NanoLogLine & logline)
{
    atomic_nanologger.load(std::memory_order_acquire)->add(std::move(logline));
    return true;
}

void initialize(NonGuaranteedLogger ngl, std::string const & log_directory, std::string const & log_file_name, std::uint32_t log_file_roll_size_mb)
{
    nanologger.reset(new NanoLogger(ngl, log_directory, log_file_name, log_file_roll_size_mb));
    atomic_nanologger.store(nanologger.get(), std::memory_order_seq_cst);
    // init is ready - level is NONE
    LogControl::instance().set_logFormat(LogFormat::LF_ALL);
    set_logLevel(LogLevel::CRIT);
}

void initialize(GuaranteedLogger gl, std::string const & log_directory, std::string const & log_file_name, std::uint32_t log_file_roll_size_mb)
{
    nanologger.reset(new NanoLogger(gl, log_directory, log_file_name, log_file_roll_size_mb));
    atomic_nanologger.store(nanologger.get(), std::memory_order_seq_cst);
    // init is ready - level is NONE
    LogControl::instance().set_logFormat(LogFormat::LF_ALL);
    set_logLevel(LogLevel::CRIT);
}

void set_logLevel(LogLevel level) noexcept
{
    if( uint8_t(level) > uint8_t(LogLevel::CRIT)) {
        LogControl::instance().set_logLevel(static_cast<unsigned int>(LogLevel::NONE));
        return;
    }
    LogControl::instance().set_logLevel(static_cast<unsigned int>(level));
}

void set_logFormat(LogFormat val) noexcept
{
    LogControl::instance().set_logFormat(val);
}

bool is_logged(LogLevel level, LogControl::value_type mask) noexcept
{
    return (static_cast<unsigned int>(level) >= LogControl::instance().get_logLevel()) &&
            LogControl::instance().is_categorySet(mask);
}

} // namespace nanologger
