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
 * @file HelloWorldSubscriber.cpp
 *
 */

#include "HelloWorldSubscriber.h"
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/subscriber/qos/DataReaderQos.hpp>

using namespace eprosima::fastdds::dds;

HelloWorldSubscriber::HelloWorldSubscriber(unsigned int domain_id)
    : id_(domain_id)
    , participant_(nullptr)
    , subscriber_(nullptr)
    , topic_(nullptr)
    , reader_(nullptr)
    , type_(new HelloWorldPubSubType())
{
}

bool HelloWorldSubscriber::init(std::string type, std::string tcti_options)
{
    //CREATE THE PARTICIPANT
    DomainParticipantQos pqos;

    if (type == "secure" || type == "uni" || type == "bid")
    {
        pqos.properties().properties().emplace_back("dds.sec.auth.plugin", "builtin.PKI-DH");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.identity_ca", "file://certs/maincacert.pem");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.identity_certificate", "file://certs/mainsubcert.pem");
        pqos.properties().properties().emplace_back("dds.sec.auth.builtin.PKI-DH.private_key", "file://certs/mainsubkey.pem");

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

    //CREATE THE SUBSCRIBER
    subscriber_ = participant_->create_subscriber(SUBSCRIBER_QOS_DEFAULT);
    if (subscriber_ == nullptr)
    {
        return false;
    }

    //CREATE THE TOPIC
    topic_ = participant_->create_topic("HelloWorldTopic", "HelloWorld", TOPIC_QOS_DEFAULT);
    if (topic_ == nullptr)
    {
        return false;
    }

    //CREATE THE DATAREADER
    DataReaderQos rqos = DATAREADER_QOS_DEFAULT;
    rqos.reliability().kind = BEST_EFFORT_RELIABILITY_QOS;
    rqos.durability().kind = VOLATILE_DURABILITY_QOS;

    reader_ = subscriber_->create_datareader(topic_, rqos, &listener_);
    if (reader_ == nullptr)
    {
        return false;
    }

    return true;
}

HelloWorldSubscriber::~HelloWorldSubscriber()
{
    if (reader_ != nullptr)
    {
        subscriber_->delete_datareader(reader_);
    }
    if (topic_ != nullptr)
    {
        participant_->delete_topic(topic_);
    }
    if (subscriber_ != nullptr)
    {
        participant_->delete_subscriber(subscriber_);
    }
    DomainParticipantFactory::get_instance()->delete_participant(participant_);
}

void HelloWorldSubscriber::SubListener::on_subscription_matched(
        DataReader*,
        const SubscriptionMatchedStatus&)
{
    // Nothing to do...
}

void HelloWorldSubscriber::SubListener::on_data_available(
        DataReader*)
{
   // Nothing to do...
}