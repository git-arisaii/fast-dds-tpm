#include "HelloWorldPublisher.h"
#include "HelloWorldSubscriber.h"

#include <fastrtps/Domain.h>
#include <fastrtps/log/Log.h>
#include <string>
#include <cstdlib>
#include <vector>
#include <thread>
#include <cmath>
#include <algorithm>

#include "Time.h"

using namespace eprosima;
using namespace fastrtps;
using namespace rtps;

void performConnection(
                       unsigned int domain_id,
                       std::string type,
                       std::string tcti_options)
{
    // Launch subscriber
    HelloWorldSubscriber mysub(domain_id);
    if (!mysub.init(type, tcti_options))
    {
        std::cerr << "Failed to create subscriber for domain id: " << domain_id << std::endl;
        return;
    }

    // Launch publisher
    HelloWorldPublisher mypub(domain_id);
    if (!mypub.init(type, tcti_options))
    {
        std::cerr << "Failed to create publisher for domain id: " << domain_id << std::endl;
        return;
    }

    // Create connection
    if (!mypub.connect())
    {
        std::cerr << "Failed to connect publisher for domain id: " << domain_id << std::endl;
        return;
    }
}

std::vector<int64_t> performTest(
                                 std::string type,
                                 unsigned int connections,
                                 unsigned int n,
                                 std::string tcti_options)
{
    std::vector<int64_t> results;
    for (unsigned int i = 0; i < n; i++)
    {
        std::cout << "  | Iteration " << i + 1 << " of " << n << "...  ";

        // Launch threads
        std::vector<std::thread> threads;
        int64_t start_ms = getTimeMs();
        for (unsigned int id = 0; id < connections; id++)
        {
            std::thread t(performConnection, id, type, tcti_options);
            threads.push_back(std::move(t));
        }

        // Collect threads
        for (std::thread& t : threads)
        {
            t.join();
        }
        int64_t result = getTimeMs() - start_ms;
        results.push_back(result);

        std::cout << " took " << result << "ms." << std::endl;
    }
    return results;
}

int main(
        int argc,
        char** argv)
{
    // Parse parameters
    std::string type = "bid";
    if (argc > 1)
    {
        type.assign(argv[1]);
    }
    if (type != "none" && type != "secure" && type != "uni" && type != "bid")
    {
        std::cerr << "Type must be one of [none, secure, uni, bid]" << std::endl;
        return -1;
    }

    int connections = 1;
    if (argc > 2)
    {
        connections = strtol(argv[2], nullptr, 10);
    }
    if (connections < 1 || connections > 200)
    {
        std::cerr << "Connections must be in range [1, 200]" << std::endl;
        return -1;
    }

    int n = 10;
    if (argc > 3)
    {
        n = strtol(argv[3], nullptr, 10);
    }
    if (n < 1)
    {
        std::cerr << "n must be 1 or greater" << std::endl;
        return -1;
    }

    std::string tcti_options = "";
    if (argc > 4)
    {
        tcti_options.assign(argv[4]);
    }

    // Perform test
    std::cout << "Performing " << n << " tests of type '" << type << "' using " << connections << " parallel connections..." << std::endl;
    std::vector<int64_t> results = performTest(type, connections, n, tcti_options);
    std::cout << "Finished." << std::endl << std::endl;

    // Calculate results
    double mean = 0;
    for(int64_t r : results)
        mean += r;
    mean = mean / results.size();

    double ssd = 0;
    for(int64_t r : results)
        ssd += (r - mean) * (r - mean);
    double var = ssd / (results.size() - 1);

    std::cout     << "************** Results **********************" << std::endl;
    std::cout     << "n       = " << results.size() << std::endl;
    std::cout     << "type    = " << type << std::endl;
    std::cout     << "conn    = " << connections << std::endl;
    if(!results.empty()) {
        std::cout << "min     = " << *std::min_element(results.begin(), results.end()) << "ms" << std::endl;
        std::cout << "max     = " << *std::max_element(results.begin(), results.end()) << "ms" << std::endl;
        std::cout << "mean    = " << mean << "ms" << std::endl;
        std::cout << "sigma   = " << std::sqrt(var) << "ms" << std::endl;
    }
    std::cout     << "*********************************************" << std::endl;

    // Clean up
    Domain::stopAll();
    Log::Reset();
    return 0;
}
