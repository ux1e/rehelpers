// demo.cpp — консольная демонстрация всех трёх модулей rehelpers.
//
// Запуск: ./demo [путь-к-exe-или-dll]
// Если путь не передан — по умолчанию читается examples/sample.exe
// (маленький PE-файл, собранный mingw-w64, лежит рядом для наглядности).

#include <cstdio>
#include <cstdint>
#include <fstream>
#include <vector>

#if defined(_WIN32)
  #include <windows.h>
#endif

#include "rehelpers/pattern_scanner.hpp"
#include "rehelpers/vtable_hook.hpp"
#include "rehelpers/pe_parser.hpp"
#include "greeter.hpp"

namespace {

void demo_pattern_scanner() {
    std::printf("== pattern_scanner ==\n");

    // Байты условной функции: mov rax, [rip+XXXXXXXX] — типичная сигнатура
    // с "плавающим" операндом, который меняется от сборки к сборке.
    std::uint8_t buffer[] = {
        0x55, 0x48, 0x89, 0xE5,                    // push rbp; mov rbp, rsp
        0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44,  // mov rax, [rip+0x44332211]
        0x5D, 0xC3                                 // pop rbp; ret
    };

    void* found = rehelpers::find_pattern(buffer, sizeof(buffer), "48 8B 05 ?? ?? ?? ??");
    if (found) {
        auto offset = static_cast<std::uint8_t*>(found) - buffer;
        std::printf("  сигнатура найдена по смещению %td\n", offset);
    } else {
        std::printf("  совпадений не найдено\n");
    }
}

void hooked_greet(Greeter* /*self*/) {
    std::printf("  [hook] перехвачен вызов greet()\n");
}

void demo_vtable_hook() {
    std::printf("== vtable_hook ==\n");
    Greeter* g = make_greeter(); // определён в greeter.cpp — отдельная TU

    g->greet(); // оригинал
    {
        rehelpers::VTableHook<void (*)(Greeter*)> hook(g, 0, hooked_greet);
        g->greet(); // подменённая реализация
    }
    g->greet(); // автоматически восстановлено RAII-деструктором
    delete g;
}

void demo_pe_parser(const char* path) {
    std::printf("== pe_parser (%s) ==\n", path);

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::printf("  не удалось открыть файл\n");
        return;
    }
    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(f)),
                                    std::istreambuf_iterator<char>());

    rehelpers::PeFile pe(data.data(), data.size());
    if (!pe.valid()) {
        std::printf("  не является корректным PE-файлом\n");
        return;
    }

    std::printf("  архитектура:     %s\n", pe.is64() ? "PE32+ (x64)" : "PE32 (x86)");
    std::printf("  entry point RVA: 0x%x\n", pe.entry_point_rva());
    std::printf("  image base:      0x%llx\n", static_cast<unsigned long long>(pe.image_base()));
    std::printf("  размер образа:   0x%x\n", pe.size_of_image());

    std::printf("  секции (%zu):\n", pe.sections().size());
    for (const auto& s : pe.sections()) {
        std::printf("    %-8s  VA=0x%08x  VSize=0x%06x  RawSize=0x%06x  %c%c%c\n",
                     s.name.c_str(), s.virtual_address, s.virtual_size, s.size_of_raw_data,
                     s.readable() ? 'R' : '-', s.writable() ? 'W' : '-',
                     s.executable() ? 'X' : '-');
    }

    auto dlls = pe.imported_dlls();
    std::printf("  импортируемые DLL (%zu):\n", dlls.size());
    for (const auto& d : dlls) {
        std::printf("    %s\n", d.c_str());
    }
}

} // namespace

int main(int argc, char** argv) {
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    demo_pattern_scanner();
    std::printf("\n");
    demo_vtable_hook();
    std::printf("\n");
    const char* pe_path = argc > 1 ? argv[1] : "sample.exe";
    demo_pe_parser(pe_path);
    return 0;
}
