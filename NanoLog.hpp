#ifndef NANO_LOG_HEADER_GUARD
#define NANO_LOG_HEADER_GUARD
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

#include <cstdint>
#include <memory>
#include <string>
#include <iosfwd>
#include <type_traits>
#include <thread>

namespace nanolog
{
enum class LogLevel : uint8_t
{
    DEBUG,
    TRACE,
    INFO,
    WARN,
    CRIT,
// SKIPPED internal is non-garanted skipped a msg
    SKIPPED,
// NONE is the highest -- disable logging
    NONE
};

enum LogFormat : uint8_t
{
    LF_NONE        = 0,
    LF_DATE_TIME   = 0x01,
    LF_THREAD      = 0x02,
    LF_FILE_FUNC   = 0x04,
    LF_ALL         = 0xFF
};

constexpr size_t LINEBUFFER_SIZE = 256;

void set_log_level(LogLevel level);

void set_log_format(LogFormat format);

bool is_logged(LogLevel level);

class NanoLogLine final
{
public:
    NanoLogLine(LogLevel level, char const * file, char const * function, uint32_t line);
    NanoLogLine(); // for init
    ~NanoLogLine()  = default;

    NanoLogLine(NanoLogLine &&) = default;
    NanoLogLine& operator=(NanoLogLine &&) = default;

    void stringify(std::ostream & os);

    NanoLogLine& operator<<(char arg);
    NanoLogLine& operator<<(int16_t arg);
    NanoLogLine& operator<<(uint16_t arg);
    NanoLogLine& operator<<(int32_t arg);
    NanoLogLine& operator<<(uint32_t arg);
    NanoLogLine& operator<<(int64_t arg);
    NanoLogLine& operator<<(uint64_t arg);
    NanoLogLine& operator<<(float arg);
    NanoLogLine& operator<<(double arg);
    NanoLogLine& operator<<(void * arg);
    
    // MUST NOT CONTAIN \0
    NanoLogLine& operator<<(std::string const & arg);

    template < size_t N >
    NanoLogLine& operator<<(const char (&arg)[N])
    {
        encode(string_literal_t(arg));
        return *this;
    }

    template < typename Arg >
    typename std::enable_if < std::is_same < Arg, char const * >::value, NanoLogLine& >::type
    operator<<(Arg const & arg)
    {
        encode(arg);
        return *this;
    }

    template < typename Arg >
    typename std::enable_if < std::is_same < Arg, char * >::value, NanoLogLine& >::type
    operator<<(Arg const & arg)
    {
        encode(arg);
        return *this;
    }

    struct string_literal_t
    {
        explicit string_literal_t(char const * s)
        : m_s(s) {}
        char const * m_s;
    };
    
    struct truncated_t
    {};
    
    void set_skipped()
    {
        m_loglevel = LogLevel::SKIPPED;
    }
private:
    char * buffer();

    template < typename Arg >
    void encode(Arg arg);

    template < typename Arg >
    void encode(Arg arg, uint8_t type_id);

    void encode(char * arg);
    void encode(char const * arg);
    void encode(string_literal_t arg);
    void encode_c_string(char const * arg, size_t length);
    void resize_buffer_if_needed(size_t additional_bytes);
    void stringify(std::ostream & os, char * start, char const * const end) const;

    uint32_t            m_bytes_used;
    uint32_t            m_buffer_size;
    std::unique_ptr < char [] > m_heap_buffer;
    uint64_t            m_timestamp;
    string_literal_t    m_file;
    string_literal_t    m_function;    
    std::thread::id     m_thread_id;
    uint32_t            m_line;
    LogLevel            m_loglevel;

    char m_stack_buffer[ LINEBUFFER_SIZE
        - sizeof(m_bytes_used)
        - sizeof(m_buffer_size)
        - sizeof(decltype(m_heap_buffer))
        - sizeof(m_timestamp)
        - sizeof(m_file)
        - sizeof(m_function)
        - sizeof(m_thread_id)    
        - sizeof(m_line)
        - sizeof(m_loglevel)
        - 8 /* Reserved */
    ];
};

struct NanoLog final
{
    bool operator==(NanoLogLine &);
};

/*
 * Non guaranteed logging. Uses a ring buffer to hold log lines.
 * When the ring gets full, the previous log line in the slot will be dropped.
 * Does not block producer even if the ring buffer is full.
 * ring_buffer_size_mb - LogLines are pushed into a mpsc ring buffer whose size
 * is determined by this parameter. Since each LogLine is 256 bytes,
 * ring_buffer_size = ring_buffer_size_mb * 1024 * 1024 / 256
 */
struct NonGuaranteedLogger final
{
    NonGuaranteedLogger(uint32_t ring_buffer_size_mb_) 
    : ring_buffer_size_mb(ring_buffer_size_mb_) 
    {}
    uint32_t ring_buffer_size_mb;
};

/*
 * Provides a guarantee log lines will not be dropped.
 */
struct GuaranteedLogger final
{
};

/*
 * Ensure initialize() is called prior to any log statements.
 * log_directory - where to create the logs. For example - "/tmp/"
 * log_file_name - root of the file name. For example - "nanolog"
 * This will create log files of the form -
 * /tmp/nanolog.1.txt
 * /tmp/nanolog.2.txt
 * etc.
 * log_file_roll_size_mb - mega bytes after which we roll to next log file.
 */
void initialize(GuaranteedLogger gl, std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb);
void initialize(NonGuaranteedLogger ngl, std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb);

} // namespace nanolog

#define NANO_LOG(LEVEL) nanolog::NanoLog() == nanolog::NanoLogLine(LEVEL, __FILE__, __func__, __LINE__)
#define LOG_DEBUG nanolog::is_logged(nanolog::LogLevel::DEBUG) && NANO_LOG(nanolog::LogLevel::DEBUG)
#define LOG_TRACE nanolog::is_logged(nanolog::LogLevel::TRACE) && NANO_LOG(nanolog::LogLevel::TRACE)
#define LOG_INFO nanolog::is_logged(nanolog::LogLevel::INFO) && NANO_LOG(nanolog::LogLevel::INFO)
#define LOG_WARN nanolog::is_logged(nanolog::LogLevel::WARN) && NANO_LOG(nanolog::LogLevel::WARN)
#define LOG_CRIT nanolog::is_logged(nanolog::LogLevel::CRIT) && NANO_LOG(nanolog::LogLevel::CRIT)

#endif /* NANO_LOG_HEADER_GUARD */

