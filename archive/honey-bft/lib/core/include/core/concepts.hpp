#pragma once

#include <concepts>
#include <coroutine>
#include <optional>
#include <ranges>
#include <utility>

namespace Honey::BFT {

// --- Awaiter concept must be defined first ---
// An Awaiter is the object returned by co_await, which has these three methods.
template <typename T>
concept IsAwaiter = requires(T a, std::coroutine_handle<> h) {
    { a.await_ready() } -> std::convertible_to<bool>;
    a.await_suspend(h);
    a.await_resume();
};

// --- The get_awaiter helper must be FULLY DEFINED next ---
// It finds the awaiter for a given type by checking for member, then non-member co_await.
template <typename T>
[[nodiscard]] constexpr auto get_awaiter(T&& value)
{
    if constexpr (requires { std::forward<T>(value).operator co_await(); }) {
        return std::forward<T>(value).operator co_await();
    } else if constexpr (requires { operator co_await(std::forward<T>(value)); }) {
        return operator co_await(std::forward<T>(value));
    } else {
        // If no co_await operator, the object might be an awaiter itself.
        return std::forward<T>(value);
    }
}

// --- The Awaitable concept can now be defined correctly ---
// It uses the fully-defined get_awaiter, breaking the circular dependency.
template <typename T>
concept Awaitable = IsAwaiter<decltype(get_awaiter(std::declval<T>()))>;

// --- AwaitableOf concept can now also be defined correctly ---
template <typename T, typename U>
concept AwaitableOf = Awaitable<T> && requires(decltype(get_awaiter(std::declval<T>())) a) {
    // Check that what you get from await_resume() is convertible to U.
    { a.await_resume() } -> std::convertible_to<U>;
};

// --- AsyncStreamOf concept depends on the above correct concepts ---
template <typename T, typename ValueT>
concept AsyncStreamOf = requires(T& stream) {
    { stream.next() } -> AwaitableOf<std::optional<ValueT>>;
};

template <typename R, typename ValueT>
concept AsyncInputRangeOf = std::ranges::range<R> && requires(R& r) {
    requires Awaitable<decltype(*std::ranges::begin(r))>;
} && std::same_as<std::ranges::range_value_t<R>, ValueT>;

} // namespace Honey::BFT
