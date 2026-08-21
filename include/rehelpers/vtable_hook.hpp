// vtable_hook.hpp
//
// RAII-обёртка для перехвата виртуального метода через подмену записи
// в vtable объекта. Оригинальный указатель сохраняется и автоматически
// восстанавливается в деструкторе (unhook при выходе из области видимости).
//
// Технически: указатель на vtable объекта лежит по адресу самого объекта
// (первые 8/4 байта, если у класса есть виртуальные функции). Эта область
// памяти обычно доступна только на чтение (.rodata / .rdata), поэтому перед
// записью снимается защита страницы (mprotect на Linux, VirtualProtect на
// Windows) и возвращается обратно после записи.
//
// Ограничения (сознательно, чтобы не разрастаться за пределы демо):
//  - рассчитан на простое одиночное наследование (Itanium ABI и MSVC ABI
//    в этом случае кладут индекс 0 = первый объявленный виртуальный метод);
//  - не обрабатывает случай, когда запись в vtable оказывается на границе
//    двух страниц памяти;
//  - не потокобезопасен: если объект хукается из нескольких потоков
//    одновременно, нужна дополнительная синхронизация — здесь её нет.

#pragma once

#include <cstdint>
#include <cstddef>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <sys/mman.h>
  #include <unistd.h>
#endif

namespace rehelpers {

namespace detail {

inline std::size_t page_size() {
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return static_cast<std::size_t>(si.dwPageSize);
#else
    return static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
#endif
}

// Пишет value по адресу target, временно сняв защиту страницы.
inline void write_protected(void** target, void* value) {
    const std::size_t ps = page_size();
    auto addr = reinterpret_cast<std::uintptr_t>(target);
    auto page_start = reinterpret_cast<void*>(addr & ~(ps - 1));

#if defined(_WIN32)
    DWORD old_protect;
    VirtualProtect(page_start, ps, PAGE_READWRITE, &old_protect);
    *target = value;
    VirtualProtect(page_start, ps, old_protect, &old_protect);
#else
    mprotect(page_start, ps, PROT_READ | PROT_WRITE);
    *target = value;
    mprotect(page_start, ps, PROT_READ);
#endif
}

} // namespace detail

// Fn — тип указателя на функцию-детур, например void(*)(MyClass*).
template <typename Fn>
class VTableHook {
public:
    // obj    — указатель на полиморфный объект (должен иметь vtable);
    // index  — индекс виртуального метода (0 = первый объявленный virtual);
    // detour — функция-перехватчик с тем же ABI, что и оригинал
    //          (обычно: свободная функция, первым параметром — this).
    VTableHook(void* obj, std::size_t index, Fn detour)
        : vtable_(*reinterpret_cast<void***>(obj)), index_(index) {
        original_ = vtable_[index_];
        detail::write_protected(&vtable_[index_], reinterpret_cast<void*>(detour));
    }

    ~VTableHook() {
        if (vtable_) {
            detail::write_protected(&vtable_[index_], original_);
        }
    }

    VTableHook(const VTableHook&) = delete;
    VTableHook& operator=(const VTableHook&) = delete;

    VTableHook(VTableHook&& other) noexcept
        : vtable_(other.vtable_), index_(other.index_), original_(other.original_) {
        other.vtable_ = nullptr;
    }

    Fn original() const { return reinterpret_cast<Fn>(original_); }

private:
    void** vtable_;
    std::size_t index_;
    void* original_;
};

} // namespace rehelpers
