// Copyright 2016 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Modified by Paul Wagner, Fraunhofer IOSB, 2024

/**
 * @file HelloWorldPublisher.cpp
 *
 */
 
#include "HelloWorldPublisher.h"

#include <chrono>
#include <thread>

#include <fastdds/dds/domain/DomainParticipantFactory.hpp>

using namespace eprosima::fastdds::dds;

HelloWorldPublisher::HelloWorldPublisher(unsigned int domain_id)
    : id_(domain_id)
    , participant_(nullptr)
    , publisher_(nullptr)
    , topic_(nullptr)
    , type_(new HelloWorldPubSubType())
    , listener_(domain_id)
{
}

bool HelloWorldPublisher::init(std::string type, std::string tcti_options)
{
    //CREATE THE PARTICIPANT
    DomainParticipantQos pqos;

    if (type == "secure" || type == "uni" || type == "bid")
    {
        pqos.properties().properties().emplace_back("dds.sec.auth.plugin", "builtin.PKI-DH");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.identity_ca", "file://certs/maincacert.pem");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.identity_certificate", "file://certs/mainpubcert.pem");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.private_key", "file://certs/mainpubkey.pem");

        pqos.properties().properties().emplace_back("dds.sec.access.plugin", "builtin.Access-Permissions");
        pqos.properties().properties().emplace_back("dds.sec.access.builtin.Access-Permissions.permissions_ca", "file://certs/maincacert.pem");
        pqos.properties().properties().emplace_back("dds.sec.access.builtin.Access-Permissions.governance", "file://certs/governance.smime");
        pqos.properties().properties().emplace_back("dds.sec.crypto.plugin", "builtin.AES-GCM-GMAC");
    }

    if (type == "secure")
    {
        pqos.properties().properties().emplace_back("dds.sec.access.builtin.Access-Permissions.permissions", "file://certs/permissions.smime");
    }
    else if (type == "uni")
    {
        pqos.properties().properties().emplace_back("dds.sec.access.builtin.Access-Permissions.permissions", "file://certs/permissions_tpm_uni.smime");

        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.privacy_ca", "file://certs/maincacert.pem");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.quoting_cert", "file://certs/quotingcert.pem");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.quoting_key", "object:certs/quotingkey.tr");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.pcr_banks", "sha256");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.pcr_selection", "16");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.tcti_options", tcti_options.c_str());
    }
    else if (type == "bid")
    {
        pqos.properties().properties().emplace_back("dds.sec.access.builtin.Access-Permissions.permissions", "file://certs/permissions_tpm_bid.smime");

        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.privacy_ca", "file://certs/maincacert.pem");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.quoting_cert", "file://certs/quotingcert.pem");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.quoting_key", "object:certs/quotingkey.tr");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.pcr_banks", "sha256");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.pcr_selection", "16");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.tpm2.tcti_options", tcti_options.c_str());
    }

    participant_ = DomainParticipantFactory::get_instance()->create_participant(id_, pqos);

    if (participant_ == nullptr)
    {
        return false;
    }

    //REGISTER THE TYPE
    type_.register_type(participant_);

    //CREATE THE PUBLISHER
    publisher_ = participant_->create_publisher(PUBLISHER_QOS_DEFAULT);
    if (publisher_ == nullptr)
    {
        return false;
    }

    //CREATE THE TOPIC
    topic_ = participant_->create_topic("HelloWorldTopic", "HelloWorld", TOPIC_QOS_DEFAULT);
    if (topic_ == nullptr)
    {
        return false;
    }

    wqos_ = DATAWRITER_QOS_DEFAULT;
    wqos_.reliability().kind = BEST_EFFORT_RELIABILITY_QOS;
    wqos_.durability().kind = VOLATILE_DURABILITY_QOS;

    return true;
}

HelloWorldPublisher::~HelloWorldPublisher()
{
    if (publisher_ != nullptr)
    {
        participant_->delete_publisher(publisher_);
    }
    if (topic_ != nullptr)
    {
        participant_->delete_topic(topic_);
    }
    DomainParticipantFactory::get_instance()->delete_participant(participant_);
}

void HelloWorldPublisher::PubListener::on_publication_matched(
        eprosima::fastdds::dds::DataWriter*,
        const eprosima::fastdds::dds::PublicationMatchedStatus& info)
{
    if (info.current_count_change == 1)
    {
        matched_ = info.total_count;
        first_connected_ = true;
    }
    else if (info.current_count_change == -1)
    {
        matched_ = info.total_count;
    }
    else
    {
        std::cout << info.current_count_change
                  << " is not a valid value for PublicationMatchedStatus current count change" << std::endl;
    }
}

bool HelloWorldPublisher::connect()
{
    DataWriter* writer = publisher_->create_datawriter(topic_, wqos_, &listener_);
    if (writer == nullptr)
    {
        return false;
    }

    // Wait for connection
    while (listener_.matched_ == 0 && !listener_.first_connected_)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    publisher_->delete_datawriter(writer);
    return true;
}
