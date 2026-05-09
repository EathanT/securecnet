from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout


class SecureCNetConan(ConanFile):
    name = "securecnet"
    version = "0.3.0"
    description = "Secure message-oriented UDP transport for C++20 applications."
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "build_tests": [True, False],
        "build_examples": [True, False],
        "build_benchmarks": [True, False],
    }
    default_options = {
        "shared": False,
        "build_tests": False,
        "build_examples": False,
        "build_benchmarks": False,
    }
    requires = "libsodium/[>=1.0.18 <2]"
    generators = "CMakeDeps", "CMakeToolchain"

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        toolchain = CMakeToolchain(self)
        toolchain.variables["SECURECNET_BUILD_SHARED"] = self.options.shared
        toolchain.variables["SECURECNET_BUILD_TESTS"] = self.options.build_tests
        toolchain.variables["SECURECNET_BUILD_EXAMPLES"] = self.options.build_examples
        toolchain.variables["SECURECNET_BUILD_BENCHMARKS"] = self.options.build_benchmarks
        toolchain.variables["SECURECNET_BUILD_DEMO"] = False
        toolchain.variables["SECURECNET_BUILD_DOC_SNIPPETS"] = False
        toolchain.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["securecnet"]
