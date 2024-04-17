This example needs the certificates stored in "certs" directory. You need to
copy this folder where you will execute the example executable. The
CMakeList.txt file also copies this directory to the folder used to build the
example.

In addition, you need to set up a TPM simulator and create a new quoting key together with a corresponding certificate.
You can call ./generate_quoting_key.sh <subjectName> to do this.
This will create a new quoting key under the first available permanent TPM handle, using the default endorsement key (EK) at position 0x81010001.
If your TPM is not already provisioned with such an EK, you can create one using the command 'tpm2_createek -c 0x81010001 -G rsa -g sha256'.
The ./generate_quoting_key.sh script will also create a quotingkey.tr file representing the generated TPM key, as well as a quotingcert.pem file containing the corresponding certificate, in the certs/ directory.

To launch this test use the following command: ./DDSPerformanceTestWithTPMExample <type> <connections> <n> <tcti_options>
<type> must be one of [none, secure, uni, bid]. Default: bid.
<connections> specifies the number of parallel connections to perform. Default: 1.
<n> specifies the number of tests to perform. Default: 10.
<tcti_options> specifies additional options for the TCTI. Default: empty.
