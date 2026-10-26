import httpant.dependencies.msquic;
import std;
import httpant.dependencies.boost.ut;

const MsQuicApi* MsQuic = nullptr;

auto main(int argc, const char** argv) -> int {
    return boost::ut::cfg<>.run({.argc = argc, .argv = argv}) ? 1 : 0;
}
