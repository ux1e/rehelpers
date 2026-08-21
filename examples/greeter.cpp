#include "greeter.hpp"
#include <cstdio>

void Greeter::greet() { std::printf("  оригинальный greet()\n"); }
Greeter::~Greeter() = default;

Greeter* make_greeter() { return new Greeter(); }
