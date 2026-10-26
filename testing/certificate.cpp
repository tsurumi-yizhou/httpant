import std;
import httpant.dependencies.wolfssl;

namespace {
int check(int result, std::string_view action) {
    if (result < 0) throw std::runtime_error(std::format("{}: wolfSSL error {}", action, result));
    return result;
}
struct random_source {
    WC_RNG value{};
    random_source() { check(wc_InitRng(&value), "initialize random source"); }
    ~random_source() { wc_FreeRng(&value); }
};
struct private_key {
    ecc_key value{};
    private_key() { check(wc_ecc_init(&value), "initialize EC key"); }
    ~private_key() { wc_ecc_free(&value); }
};
bool current(const std::filesystem::path& cert, const std::filesystem::path& key) {
    if (!std::filesystem::exists(key)) return false;
    auto* parsed = wolfSSL_X509_load_certificate_file(cert.string().c_str(), WOLFSSL_FILETYPE_PEM);
    if (!parsed) return false;
    const unsigned char* date = nullptr;
    unsigned char format = 0;
    int length = 0;
    std::tm calendar{};
    auto info = wc_GetDateInfo(wolfSSL_X509_notAfter(parsed), 32, &date, &format, &length);
    auto result = info == 0 ? wc_GetDateAsCalendarTime(date, length, format, &calendar) : info;
    wolfSSL_X509_free(parsed);
    if (result != 0) return false;
    using namespace std::chrono;
    auto expires = sys_days{year{calendar.tm_year + 1900}/month{unsigned(calendar.tm_mon + 1)}/day{unsigned(calendar.tm_mday)}} +
        hours{calendar.tm_hour} + minutes{calendar.tm_min} + seconds{calendar.tm_sec};
    return expires > system_clock::now() + days{1};
}
void date(unsigned char* output, int& size, std::chrono::sys_seconds time) {
    auto text = std::format("{:%Y%m%d%H%M%S}Z", time);
    output[0] = 0x18;
    output[1] = static_cast<unsigned char>(text.size());
    std::memcpy(output + 2, text.data(), text.size());
    size = static_cast<int>(text.size() + 2);
}
void pem(const std::filesystem::path& path, std::span<const unsigned char> der, int type) {
    std::array<unsigned char, 8192> output;
    auto size = check(wc_DerToPem(der.data(), der.size(), output.data(), output.size(), type), "encode PEM");
    std::ofstream file{path, std::ios::binary | std::ios::trunc};
    file.exceptions(std::ios::badbit | std::ios::failbit);
    file.write(reinterpret_cast<const char*>(output.data()), size);
    file.close();
}
}

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::invalid_argument("expected an existing build directory");
        std::filesystem::path directory{argv[1]};
        if (!std::filesystem::is_directory(directory)) throw std::invalid_argument("build directory does not exist");
        if (wolfSSL_Init() != WOLFSSL_SUCCESS) throw std::runtime_error("TLS initialization failed");
        auto cert_path = directory / "quic-cert.pem", key_path = directory / "quic-key.pem";
        if (current(cert_path, key_path)) return 0;
        random_source random;
        private_key key;
        check(wc_ecc_make_key_ex(&random.value, 32, &key.value, ECC_SECP256R1), "generate P-256 key");
        Cert cert{};
        check(wc_InitCert(&cert), "initialize certificate");
        auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
        date(cert.beforeDate, cert.beforeDateSz, now);
        date(cert.afterDate, cert.afterDateSz, now + std::chrono::days{7});
        cert.sigType = CTC_SHA256wECDSA;
        std::strcpy(cert.subject.commonName, "localhost");
        constexpr unsigned char san[]{0x30, 0x0b, 0x82, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'};
        check(wc_SetCustomExtension(&cert, 0, "2.5.29.17", san, sizeof(san)), "set localhost SAN");
        std::array<unsigned char, 4096> der;
        auto size = check(wc_MakeCert(&cert, der.data(), der.size(), nullptr, &key.value, &random.value), "generate certificate");
        size = check(wc_SignCert(size, cert.sigType, der.data(), der.size(), nullptr, &key.value, &random.value), "sign certificate");
        pem(cert_path, {der.data(), static_cast<std::size_t>(size)}, CERT_TYPE);
        size = check(wc_EccKeyToDer(&key.value, der.data(), der.size()), "encode key");
        pem(key_path, {der.data(), static_cast<std::size_t>(size)}, ECC_PRIVATEKEY_TYPE);
        std::filesystem::permissions(key_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        return 0;
    } catch (const std::exception& error) {
        std::println(std::cerr, "certificate: {}", error.what());
        return 1;
    }
}
