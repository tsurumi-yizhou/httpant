export module httpant.queue;
import std;

export namespace http::queues {
    template <class Q, class T>
    concept queue = requires(Q& q, T value) {
        { q.push(std::move(value)) } -> std::same_as<bool>;
        { q.try_pop(value) } -> std::same_as<bool>;
    };

    template <class T> class local {
        std::deque<T> items_;
    public:
        auto push(T value) -> bool { items_.push_back(std::move(value)); return true; }
        auto try_pop(T& value) -> bool {
            if (items_.empty()) return false;
            value = std::move(items_.front());
            items_.pop_front();
            return true;
        }
    };

    template <class T> class locked {
        std::mutex mutex_;
        local<T> items_;
    public:
        auto push(T value) -> bool { std::lock_guard lock{mutex_}; return items_.push(std::move(value)); }
        auto try_pop(T& value) -> bool { std::lock_guard lock{mutex_}; return items_.try_pop(value); }
    };

    template <class T, template <class> class Queue = local>
        requires queue<Queue<T>, T>
    class buffer {
        Queue<T> items_;
        std::optional<T> first_;
        std::size_t size_ = 0;
    public:
        void push_back(T value) {
            if (!items_.push(std::move(value))) throw std::system_error(std::make_error_code(std::errc::no_buffer_space));
            ++size_;
        }
        template <class... Args> void emplace_back(Args&&... args) { push_back(T(std::forward<Args>(args)...)); }
        auto empty() const noexcept -> bool { return size_ == 0; }
        auto size() const noexcept -> std::size_t { return size_; }
        auto front() -> T& {
            if (!first_) {
                T value{};
                if (!items_.try_pop(value)) std::terminate();
                first_.emplace(std::move(value));
            }
            return *first_;
        }
        void pop_front() { static_cast<void>(front()); first_.reset(); --size_; }
        void clear() { while (!empty()) pop_front(); }
        template <class Function> void each(Function function) {
            auto count = size_;
            while (count--) {
                auto value = std::move(front());
                pop_front();
                function(value);
                push_back(std::move(value));
            }
        }
    };
}
