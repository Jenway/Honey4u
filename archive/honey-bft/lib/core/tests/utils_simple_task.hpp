#pragma once

#include <coroutine>
#include <exception>
#include <utility>

// A minimal eager coroutine Task that runs to completion immediately.
template <typename T>
class InlineTask {
public:
    struct promise_type {
        T value {};
        std::exception_ptr ep;

        InlineTask get_return_object()
        {
            return InlineTask { std::coroutine_handle<promise_type>::from_promise(*this) };
        }

        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }

        void return_value(T v) { value = std::move(v); }

        void unhandled_exception() { ep = std::current_exception(); }
    };

    explicit InlineTask(std::coroutine_handle<promise_type> h)
        : handle_(h)
    {
    }

    InlineTask(InlineTask&& other) noexcept
        : handle_(std::exchange(other.handle_, {}))
    {
    }

    InlineTask(const InlineTask&) = delete;
    InlineTask& operator=(const InlineTask&) = delete;

    ~InlineTask()
    {
        if (handle_)
            handle_.destroy();
    }

    auto operator co_await()
    {
        struct Awaiter {
            std::coroutine_handle<promise_type> h;
            bool await_ready() const noexcept { return true; }
            void await_suspend(std::coroutine_handle<>) const noexcept { }
            T await_resume()
            {
                if (h.promise().ep)
                    std::rethrow_exception(h.promise().ep);
                return std::move(h.promise().value);
            }
        };
        return Awaiter { handle_ };
    }

    T get()
    {
        if (handle_.promise().ep)
            std::rethrow_exception(handle_.promise().ep);
        T v = std::move(handle_.promise().value);
        handle_.destroy();
        handle_ = {};
        return v;
    }

private:
    std::coroutine_handle<promise_type> handle_ {};
};

template <>
class InlineTask<void> {
public:
    struct promise_type {
        InlineTask get_return_object()
        {
            return InlineTask { std::coroutine_handle<promise_type>::from_promise(*this) };
        }

        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void return_void() noexcept { }
        void unhandled_exception() { ep = std::current_exception(); }

        std::exception_ptr ep;
    };

    explicit InlineTask(std::coroutine_handle<promise_type> h)
        : handle_(h)
    {
    }

    InlineTask(InlineTask&& other) noexcept
        : handle_(std::exchange(other.handle_, {}))
    {
    }

    InlineTask(const InlineTask&) = delete;
    InlineTask& operator=(const InlineTask&) = delete;

    ~InlineTask()
    {
        if (handle_)
            handle_.destroy();
    }

    auto operator co_await()
    {
        struct Awaiter {
            std::coroutine_handle<promise_type> h;
            bool await_ready() const noexcept { return true; }
            void await_suspend(std::coroutine_handle<>) const noexcept { }
            void await_resume()
            {
                if (h.promise().ep)
                    std::rethrow_exception(h.promise().ep);
            }
        };
        return Awaiter { handle_ };
    }

    void get()
    {
        if (handle_.promise().ep)
            std::rethrow_exception(handle_.promise().ep);
        handle_.destroy();
        handle_ = {};
    }

private:
    std::coroutine_handle<promise_type> handle_ {};
};
