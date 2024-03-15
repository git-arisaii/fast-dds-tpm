This example needs the certificates stored in "certs" directory. You need to
copy this folder where you will execute the example executable. The
CMakeList.txt file also copies this directory to the folder used to build the
example.

In addition, you need to set up a TPM simulator and create a new quoting key together with a corresponding certificate.
You can call ./generate_quoting_key.sh <subjectName> to do this.
This will create a new quoting key under the first available permanent TPM handle, using the default endorsement key (EK) at position 0x81010001.
If your TPM is not already provisioned with such an EK, you can create one using the command 'tpm2_createek -c 0x81010001 -G rsa -g sha256'.
The ./generate_quoting_key.sh script will also create a quotingkey.tr file representing the generated TPM key, as well as a quotingcert.pem file containing the corresponding certificate, in the certs/ directory.

To launch this test open two different consoles:

In the first one launch: ./DDSSecureHelloWorldWithTPMExample publisher (or DDSSecureHelloWorldWithTPMExample.exe publisher on windows).
In the second one: ./DDSSecureHelloWorldWithTPMExample subscriber (or DDSSecureHelloWorldWithTPMExample.exe subscriber on windows).

This will conduct a bidirectional remote attestation between publisher and subscriber.
To deactivate the generation of quotes for one participant, use the "noatt" option.
For example, to conduct a unidirectional attestation of the prover only, use: ./DDSSecureHelloWorldWithTPMExample subscriber noatt

