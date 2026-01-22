#pragma once

#include <concepts>
#include <coroutine>
#include <optional>
#include <ranges>
#include <utility>

namespace Honey::BFT {

template <typename T>
concept IsAwaiter = requires(T a, std::coroutine_handle<> h) {
    { a.await_ready() } -> std::convertible_to<bool>;
    a.await_suspend(h);
    a.await_resume();
};

template <typename T>
[[nodiscard]] constexpr auto get_awaiter(T&& value)
{
    if constexpr (requires { std::forward<T>(value).operator co_await(); }) {
        return std::forward<T>(value).operator co_await();
    } else if constexpr (requires { operator co_await(std::forward<T>(value)); }) {
        return operator co_await(std::forward<T>(value));
    } else {
        return std::forward<T>(value);
    }
}

template <typename T>
concept Awaitable = IsAwaiter<decltype(get_awaiter(std::declval<T>()))>;

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

template <typename T, typename Result>
concept AwaitsTo = Awaitable<T> && requires(T&& t) {
    { t.await_resume() } -> std::convertible_to<Result>;
};

template <template <typename> typename TaskT>
concept TaskModel = requires {
    typename TaskT<int>;
    typename TaskT<void>;
    typename TaskT<double>;
} && AwaitsTo<TaskT<int>, int> && AwaitsTo<TaskT<double>, double> && AwaitsTo<TaskT<void>, void>;

} // namespace Honey::BFT
