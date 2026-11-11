export module httpant.exception;
import std;

// Clang records a thrown type's copy constructor for the Microsoft ABI only
// where its own semantic analysis saw the throw. Code an importer emits from
// a module (inline functions, the module's template instantiations) throws
// with metadata lacking the copy callback, the linker may keep that copy of
// the type's throw info, and std::current_exception then copies the object
// bitwise. Captured errors are rethrown as captured<Error> from functions
// emitted only by their module unit, whose metadata is complete.
export namespace http::exceptions {
    // The handled exception, captured with its type's copy constructor.
    auto current_exception() noexcept -> std::exception_ptr;
    template <class Error> auto make_exception_ptr(Error error) noexcept -> std::exception_ptr {
        try { throw std::move(error); }
        catch (...) { return http::exceptions::current_exception(); }
    }
    // An error of the library captures itself in a member its module unit
    // emits, so it is never inline: the member returns capture(*this).
    struct exception_capture {
        virtual ~exception_capture() = default;
        virtual auto capture() const noexcept -> std::exception_ptr = 0;
    };
    template <class Error> struct captured final : Error {
        explicit captured(const Error& error) : Error(error) {}
    };
    // Called only from functions their module unit emits.
    template <class Error> auto capture(const Error& error) noexcept -> std::exception_ptr {
        try { throw captured<Error>(error); }
        catch (...) { return std::current_exception(); }
    }
}

namespace http::exceptions {
    namespace {
        template <class Error> auto own(const Error& error) noexcept -> std::exception_ptr {
            // A type derived from Error keeps its own type.
            if (typeid(error) != typeid(Error)) return std::current_exception();
            return http::exceptions::capture(error);
        }
    }
    auto current_exception() noexcept -> std::exception_ptr {
        try { throw; }
        catch (const exception_capture& error) { return error.capture(); }
        catch (const std::filesystem::filesystem_error& error) { return own(error); }
        catch (const std::ios_base::failure& error) { return own(error); }
        catch (const std::system_error& error) { return own(error); }
        catch (const std::format_error& error) { return own(error); }
        catch (const std::invalid_argument& error) { return own(error); }
        catch (const std::domain_error& error) { return own(error); }
        catch (const std::length_error& error) { return own(error); }
        catch (const std::out_of_range& error) { return own(error); }
        catch (const std::logic_error& error) { return own(error); }
        catch (const std::range_error& error) { return own(error); }
        catch (const std::overflow_error& error) { return own(error); }
        catch (const std::underflow_error& error) { return own(error); }
        catch (const std::runtime_error& error) { return own(error); }
        catch (...) { return std::current_exception(); }
    }
}
