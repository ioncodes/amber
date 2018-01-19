#include <pistache/endpoint.h>
#include <keystone/keystone.h>
#include <stdio.h>
#include <iomanip>

using namespace Pistache;

ks_engine *ks;

class HelloHandler : public Http::Handler {
public:

    HTTP_PROTOTYPE(HelloHandler)

    void onRequest(const Http::Request& request, Http::ResponseWriter response) {
        if (request.resource() == "/asm") {
            if (request.method() == Http::Method::Post) {
                size_t count;
                size_t size;
                unsigned char *encode;
                if (ks_asm(ks, request.body().c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
                    std::cout << "ERROR: ks_asm() failed & count = " << 
                        count <<
                        ", error = " <<
                        ks_errno(ks) <<
                        std::endl;
                    response.send(Http::Code::Not_Found);
                } else {
                    std::stringstream ss;
                    for(int i = 0; i < size; i++) {
                        ss << "0x" << std::setfill('0') << std::setw(2) << std::hex << int(encode[i]);
                        if(i != size - 1) {
                            ss << ",";
                        }
                    }
                    response.send(Http::Code::Ok, ss.str(), MIME(Text, Plain));
                    ks_free(encode);
                }
            } else {
                std::cout << "Method not allowed" << std::endl;
                response.send(Http::Code::Method_Not_Allowed);
            }
        } else {
            std::cout << "Not Found" << std::endl;
            response.send(Http::Code::Not_Found);
        }
    }
};

int main() {
    ks_err err;
    do {
        err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
        std::cout << "Loading Keystone" << std::endl;
    } while (err != KS_ERR_OK);
    
    Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(1337));
    auto opts = Pistache::Http::Endpoint::options()
        .threads(1);

    Http::Endpoint server(addr);
    server.init(opts);
    server.setHandler(Http::make_handler<HelloHandler>());

    std::cout << "Server started!" << std::endl;

    server.serve();

    server.shutdown();

    std::cout << "Server stopped!" << std::endl;

    ks_close(ks);

    std::cout << "Keystone unloaded!" << std::endl;

    return 0;
}
