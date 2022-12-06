// RUN: %clang_cc1 -std=c++20 -Wno-deprecated-declarations -Wunsafe-buffer-usage -verify %s

[[clang::unsafe_buffer_usage]]
void deprecatedFunction3();

void deprecatedFunction4(int z);

void someFunction();

[[clang::unsafe_buffer_usage]]
void overloading(int* x);

void overloading(char c[]);

void overloading(int* x, int size);

[[clang::unsafe_buffer_usage]]
void deprecatedFunction4(int z);

void caller(int z, int* x, int size, char c[]) {
    deprecatedFunction3(); // expected-warning{{unchecked operation on raw buffer in expression}}
    deprecatedFunction4(z); // expected-warning{{unchecked operation on raw buffer in expression}}
    someFunction();

    overloading(x); // expected-warning{{unchecked operation on raw buffer in expression}}
    overloading(x, size);
    overloading(c);
}

[[clang::unsafe_buffer_usage]]
void overloading(char c[]);
