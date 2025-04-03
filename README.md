# DMA: Mutual Attestation Framework for Distributed Enclaves

Thank you for your interest in **DMA**. This document will get you started with our prototype implementation. **DMA** is accepted by **_ICICS 2024_**, see [program](http://icics2024.aegean.gr/programs/) of accepted papers for more details. You can download the [paper](http://icics2024.aegean.gr/wp-content/uploads/2024/08/150560135.pdf) and [slides](http://icics2024.aegean.gr/wp-content/uploads/2024/10/Peixi-Li-ICICS16-1630.pdf).

## Overview of DMA
![architecture](./doc/architecture.pdf)
DMA provides strong freshness binding of the attestation evidence and uses consensus algorithms to ensure balanced trust across network domains. _AuthE_ are placed
on authentication nodes, while _AttestE_ are placed on user nodes. In addition,
function-specific user-level enclaves, referred to as user enclaves (_UserE_), are
also deployed in user nodes.


## Experiment Dependencies

To use DMA, the following conditions must be met:

1. Distributed Intel SGX machines (SGX 1 or SGX 2).

   Please check if your machine supports Intel SGX by running `cpuid | grep SGX`.

   Make sure the SGX driver is installed on your machine, visit the [linux-sgx-driver](https://github.com/intel/linux-sgx-driver) repository or the [SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/main/driver/linux) repository for more information.

2. Install the Intel SGX SDK, PSW, and DCAP libraries on all machines, regardless of whether your machine supports DCAP attestation.

   Please visit the [linux-sgx](https://github.com/intel/linux-sgx/tree/sgx_2.21) repository for more information on how to install the Intel SGX SDK, PSW, and DCAP libraries.

   **Note: You should also install the `*-dev` packages to obtain the DCAP library header files.**

3. Install the Intel SGX SSL library on all machines. For more information, visit the [intel-sgx-ssl](https://github.com/intel/intel-sgx-ssl/tree/support_tls) repository.

   ```bash
   $ wget https://github.com/01org/intel-sgx-ssl/archive/support_tls_lin_1.1.1m.zip
   $ unzip support_tls_lin_1.1.1m.zip
   $ cd intel-sgx-ssl-support_tls_lin_1.1.1m/openssl_source
   $ wget https://www.openssl.org/source/openssl-1.1.1m.tar.gz
   $ cd ../Linux
   $ bash ./build_openssl.sh
   $ make -j
   $ sudo make install
   ```

4. Fully clone the repository, including all third-party libraries contained in the `3rd-party` directory.

   ```bash
   $ git clone https://github.com/Seix61/DMA.git --recursive
   ```

5. If you need to use EPID attestation, supplement the configuration information in `include/global/general_settings.h`. For more information, visit https://api.portal.trustedservices.intel.com/EPID-attestation.

   ```cpp
   // Your EPID Service Provider ID
   static const sgx_spid_t SPId = {};
   // Your EPID Subscription Key
   static const std::string SubscriptionKey = "";
   ```

## Build

To build DMA, you can use the following commands:

```bash
$ mkdir build && cd build
$ cmake ..
$ make -j
```

You can build DMA on one machine and then distribute the build artifacts to all machines.

The following are the required build artifacts:

- `build/src/auth/AuthApp`: The host application for AuthEnclave
- `build/src/auth/enclave.signed.so`: The AuthEnclave
- `build/src/attest/AttestApp`: The host application for AttestEnclave
- `build/src/attest/enclave.signed.so`: The AttestEnclave
- `build/src/user/UserApp`: The host application for UserEnclave
- `build/src/user/enclave.signed.so`: The UserEnclave

## Run

DMA uses CLI11 to parse the runtime parameters of `AuthApp`, `AttestApp`, and `UserApp`. For details on the meaning of the parameters, please refer to the source code in `src/auth/App/src/main.cpp`, `src/attest/App/src/main.cpp`, and `src/user/App/src/main.cpp`.

We provide a Python script to quickly generate the required runtime parameters. To obtain this script, refer to `script/run_generator.py`.

**Note: You need to run the `run_generator.py` script separately on each machine.**

### Configure Node Information for run_generator

To run `run_generator.py`, create two JSON files in the directory where the script will be executed:

1. `peers.json`, which describes all the nodes deployed in the network. The template is as follows:

   ```json
   {
       "127.0.0.1": 1 // 1 AuthEnclave instance is running on the machine with IP address 127.0.0.1
   }
   ```

2. `current.json`, which describes the configuration information of the current machine. The template is as follows:

   ```json
   {
       "ip": "127.0.0.1", // The IP address of the current machine is 127.0.0.1
       "id": 1 // The ID of the current machine is 1
   }
   ```

### Run run_generator

You can use the following command to run `run_generator.py`, where the `--threads` option indicates the number of threads used for RPC communication within AuthEnclave:

```bash
$ python3 ./run_generator.py --threads 5
```

If you want to use **DCAP attestation** between AuthEnclaves and between AuthEnclave and AttestEnclave, please use the `--use_dcap` option; otherwise, EPID attestation will be used by default:

```bash
$ python3 ./run_generator.py --threads 5 --use_dcap 1
```

If you **do not wish** to perform attestation between AuthEnclaves and between AuthEnclave and AttestEnclave (usually in a testing environment), please use the `--ignore_trust` option:

```bash
$ python3 ./run_generator.py --threads 5 --ignore_trust 1
```

### Run DMA

After generating the runtime parameters, please run DMA in the following order.

1. Run AuthEnclave:

   ```bash
   $ ./AuthApp --config ./config_auth.ini
   ```

2. Run AttestEnclave:

   ```bash
   $ ./AttestApp --config ./config_attest.ini
   ```

3. Run UserEnclave:

   ```bash
   $ ./UserApp --config ./config_user.ini
   ```

## Citation
If you find this useful in your research, please consider citing:
```
@inproceedings{li2024DMA,
author = {Li, Peixi and Li, Xiang and Fang, Liming},
title = {DMA: Mutual Attestation Framework for Distributed Enclaves},
year = {2024},
isbn = {978-981-97-8797-5},
publisher = {Springer-Verlag},
address = {Berlin, Heidelberg},
url = {https://doi.org/10.1007/978-981-97-8798-2_8},
doi = {10.1007/978-981-97-8798-2_8},
booktitle = {Information and Communications Security: 26th International Conference, ICICS 2024, Mytilene, Greece, August 26–28, 2024, Proceedings, Part I},
pages = {145–164},
numpages = {20},
keywords = {Remote attestation, Intel SGX, Distributed system},
location = {Mytilene, Greece}
}
```