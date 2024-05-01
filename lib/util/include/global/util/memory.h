
#ifndef LIB_UTIL_MEMORY_H
#define LIB_UTIL_MEMORY_H

#include <memory>

class Memory {
public:
    template<typename T>
    static std::shared_ptr<T> makeShared(size_t size) {
        return std::shared_ptr<T>((T*)operator new(size));
    }

    template<typename T>
    static std::shared_ptr<T> makeShared(const T *p, size_t size) {
        return Memory::copySharedOf<T, T>(p, size);
    }

    template<typename T>
    static std::unique_ptr<T> makeUnique(size_t size) {
        return std::unique_ptr<T>((T*)operator new(size));
    }

    template<typename T>
    static std::unique_ptr<T> makeUnique(const T *p, size_t size) {
        return Memory::copyUniqueOf<T, T>(p, size);
    }

    template<typename F, typename T>
    static std::shared_ptr<T> copySharedOf(const F *from, size_t size) {
        auto ret = Memory::makeShared<T>(size);
        memcpy(ret.get(), from, size);
        return ret;
    }

    template<typename F, typename T>
    static std::unique_ptr<T> copyUniqueOf(const F *from, size_t size) {
        auto ret = Memory::makeUnique<T>(size);
        memcpy(ret.get(), from, size);
        return ret;
    }

    template<typename F, typename T>
    static std::shared_ptr<T> copyOf(const std::shared_ptr<F> &from, size_t size) {
        auto ret = Memory::makeShared<T>(size);
        memcpy(ret.get(), from.get(), size);
        return ret;
    }

    template<typename F, typename T>
    static std::unique_ptr<T> copyOf(const std::unique_ptr<F> &from, size_t size) {
        auto ret = Memory::makeUnique<T>(size);
        memcpy(ret.get(), from.get(), size);
        return ret;
    }

    template<typename T>
    static std::shared_ptr<T> copyOf(const std::shared_ptr<T> &from, size_t size) {
        return Memory::copyOf<T, T>(from, size);
    }

    template<typename T>
    static std::unique_ptr<T> copyOf(const std::unique_ptr<T> &from, size_t size) {
        return Memory::copyOf<T, T>(from, size);
    }
};

#endif //LIB_UTIL_MEMORY_H
