module;
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define HTTPANT_MEMORY_UNPOOLED 1
#endif
#endif

export module httpant.memory;
import std;

// One bounded per-thread pool shared by HTTP and application task frames.
// Sanitizer builds return frames directly to the allocator.
export namespace http::memory {
    class frames {
    public:
        static auto allocate(std::size_t size) -> void* {
            auto index = class_of(size);
#ifdef HTTPANT_MEMORY_UNPOOLED
            index = classes;
#endif
            if (index == classes)
                return ::operator new(size);
            // Blocks are always a whole size class, so any pool can reuse them.
            if (auto* pool = local()) {
                auto& list = pool->free_[index];
                if (list.count != 0) {
                    auto* block = list.head;
                    list.head = block->next;
                    --list.count;
                    return block;
                }
            }
            return ::operator new(class_size(index));
        }

        static void deallocate(void* frame, std::size_t size) noexcept {
            auto index = class_of(size);
#ifdef HTTPANT_MEMORY_UNPOOLED
            index = classes;
#endif
            auto* pool = index == classes ? nullptr : local();
            if (pool == nullptr || pool->free_[index].count >= max_cached)
                return ::operator delete(frame);
            auto& list = pool->free_[index];
            auto* block = static_cast<block_node*>(frame);
            block->next = list.head;
            list.head = block;
            ++list.count;
        }

    private:
        struct block_node {
            block_node* next;
        };
        struct free_list {
            block_node* head{nullptr};
            std::size_t count{0};
        };

        // 64 B, 128 B, ... 32 KiB; larger frames use the heap directly.
        static constexpr std::size_t first_class = 64;
        static constexpr std::size_t classes = 10;
        static constexpr std::size_t max_cached = 32;

        static constexpr auto class_size(std::size_t index) -> std::size_t { return first_class << index; }
        static constexpr auto class_of(std::size_t size) -> std::size_t {
            if (size <= first_class)
                return 0;
            return std::min<std::size_t>(classes, std::bit_width(size - 1) - 6);
        }

        explicit frames(bool* destroyed) noexcept : destroyed_(destroyed) {}
        ~frames() {
            *destroyed_ = true;
            for (auto& list : free_)
                for (auto* block = list.head; block != nullptr;) {
                    auto* next = block->next;
                    ::operator delete(block);
                    block = next;
                }
        }
        frames(const frames&) = delete;
        auto operator=(const frames&) -> frames& = delete;

        // The calling thread's pool, or null once thread teardown has destroyed
        // it: a frame freed that late goes straight back to the heap. The flag is
        // trivially destructible, so it stays readable after the pool is gone.
        static auto local() -> frames* {
            static thread_local bool destroyed = false;
            static thread_local frames pool{&destroyed};
            return destroyed ? nullptr : &pool;
        }

        bool* destroyed_;
        free_list free_[classes]{};
    };

} // namespace http::memory
