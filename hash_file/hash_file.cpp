#ifdef _MSC_VER
#include <boost/config/compiler/visualc.hpp>
#endif

#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/json.hpp>
#include <boost/nowide/args.hpp>
#include <boost/nowide/filesystem.hpp>
#include <boost/nowide/fstream.hpp>
#include <boost/nowide/iostream.hpp>
#include <charconv>
#include <iomanip>
#include <memory>
#include <mutex>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string>
#include <string_view>
#include <thread>
#include <vector>


//deleter for std::unique_ptr<BIO>
struct BIO_def_deleter { void operator()(BIO* ptr) noexcept { BIO_free_all(ptr); } };

//deleter for std::unique_ptr<EVP_MD_CTX>
struct EVP_CTX_def_deleter { void operator()(EVP_MD_CTX* ptr) noexcept { EVP_MD_CTX_free(ptr); } };

std::string md5hash_64base(std::string_view buf) {
    //md5 context init.
    std::unique_ptr<EVP_MD_CTX, EVP_CTX_def_deleter> context{ EVP_MD_CTX_new() };
    const EVP_MD* md = EVP_md5();
    std::vector<unsigned char> md_value;
    md_value.reserve(EVP_MAX_MD_SIZE);
    std::uint32_t md_len;
    std::string output;

    //hashing
    EVP_DigestInit_ex2(context.get(), md, NULL);
    EVP_DigestUpdate(context.get(), buf.data(), buf.length());
    EVP_DigestFinal_ex(context.get(), md_value.data(), &md_len);
    output.resize(md_len);
    std::memcpy(output.data(), md_value.data(), md_len);

    //base64 encode
    std::unique_ptr<BIO, BIO_def_deleter> b64(BIO_new(BIO_f_base64()));
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* sink = BIO_new(BIO_s_mem());
    BIO_push(b64.get(), sink);
    BIO_write(b64.get(), output.data(), output.length());
    BIO_flush(b64.get());
    const char* encd;
    const size_t len = BIO_get_mem_data(sink, &encd);
    return std::string{ encd, len };
}

int main(int argc, char* argv[]) {
    //aliases
    namespace fs = boost::filesystem;
    auto& out = boost::nowide::cout;

    //input data
    std::uint32_t block_size = 4096U;
    constexpr size_t THREADS_COUNT = 4;
    constexpr size_t F_ARG = 1;
    constexpr size_t S_ARG = 2;
    constexpr size_t T_ARG = 3;

    //initializing input data and assert
    if (argc < 3) {
        out << "No arguments entered! Please enter the path of the input output directory and the size of the hash block!\n";
        return 1;
    }
    boost::nowide::args arg(argc, argv);
    boost::nowide::nowide_filesystem();
    const fs::path directory{argv[F_ARG]};
    fs::path output_directory{ argv[S_ARG] };
    auto&& [ptr, erc] = std::from_chars(argv[T_ARG], argv[T_ARG] + std::strlen(argv[T_ARG]), block_size);

    //assert
    if (!fs::exists(directory)) {
        out << "Directory or file " << argv[1] << " doesn't exist!\n";
        return 1;
    } else if (!fs::exists(output_directory) && !fs::is_directory(output_directory)) {
        out << "Directory " << argv[2] << " doesn't exist or this path isn't a directory!\n";
        return 1;
    } else if (erc != std::errc{}) {
        out << "The number was entered incorrectly or exceeded the allowed value\n";
        return 1;
    }

    //configuring output data
    output_directory.append("executed.json");
    boost::nowide::ofstream file_out{ output_directory, std::ios_base::out };
    std::vector<std::thread> executors;
    boost::json::object root{ {"block size", block_size} };
    boost::json::array files_node;

    //lambda file hashing
    auto hash_file = [&block_size, &files_node](const fs::path& file_path) {
        //opening file and creating json array
        boost::nowide::ifstream file{ file_path, std::ios_base::binary };
        boost::json::array hashed_blocks;
        hashed_blocks.reserve(fs::file_size(file_path) / block_size);
        std::string content(block_size, ' ');

        //reading from file
        while (!file.eof()) {
            file.read(content.data(), block_size);
            hashed_blocks.emplace_back(std::move(md5hash_64base(content)));
        }

        //creating a json object with file properties
        boost::json::object file_properties{ {"path", file_path.string()}, {"size", fs::file_size(file_path)}, {"hash", hashed_blocks} };
        files_node.emplace_back(file_properties);
        file.close();
    };

    //directory round and processing all files
    for (const auto& file : fs::recursive_directory_iterator{ directory }) {
        executors.emplace_back(hash_file, file);

        //checking for the count of files equal to threads count and processing them
        if (executors.size() == THREADS_COUNT) {
            std::mutex mtx;
            std::unique_lock<std::mutex> lock{ mtx };
            for (auto&& thread : executors) {
                thread.join();
            }
            lock.unlock();
            executors.clear();
        }
    }

    //processing the remaining files
    for (auto&& thread : executors) {
        thread.join();
    }

    //pushing files node and write to file
    root.emplace("files", files_node);
    file_out << root;
    file_out.close();
    return 0;
}