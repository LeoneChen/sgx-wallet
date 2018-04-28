# sgx-wallet
[![license](https://img.shields.io/badge/license-GPL3-brightgreen.svg)](https://github.com/asonnino/sgx-wallet/blob/master/LICENSE)

This is a simple password-wallet application based on Intel SGX for linux. Intel also provides a full [tutorial](https://software.intel.com/en-us/articles/introducing-the-intel-software-guard-extensions-tutorial-series) and [source code](https://github.com/IntelSoftware/Tutorial-Password-Manager-with-Intel-SGX) for Windows users.


## Pre-requisites
Ensure to have the Intel SGX Linux [drivers](https://github.com/intel/linux-sgx-driver) and [SDK](https://github.com/intel/linux-sgx) installed.


## Install
Install **sgx-wallet** as follows:

  - Source the Intel SGX SDK as described [here](https://github.com/intel/linux-sgx#install-the-intelr-sgx-sdk-1); if your SDK installation path is `${sgx-sdk-install-path}`, run:
```
$ source ${sgx-sdk-install-path}/environment
```

  - Clone and build the source code:
```
$ git clone https://github.com/asonnino/sgx-wallet.git
$ cd sgx-wallet
$ make
```


## Usage
**sgx-wallet** comes with a simple cli that can be run with the following options:
  - Show help:
```
sgx-wallet -h
```

  - Show version:
```
sgx-wallet -v
```

  - Run tests:
```
sgx-wallet -t
``` 

  - create a new wallet with master-password `<master-passowrd>`:
```
sgx-wallet -n master-password
``` 

  - Change current master-password to `<new-master-password>`:
```
sgx-wallet -p master-password -c new-master-password
``` 

  - Add a new item to the wallet with title `<items_title>`, username `<items_username>`, and password `<items_password>`:
```
sgx-wallet -p master-password -a -x items_title -y items_username -z toitems_password
``` 

  - Remove item at index `<items_index>` from the wallet:
```
sgx-wallet -p master-password -r items_index
``` 
The wallet data are saved in a file called `wallet.seal` in the same directory as the main application. Note that you can have only one `wallet.seal` file, and attempting to call twice `sgx-wallet -n master-password` will result in an error.

## Contribute
Any help is welcome through PRs!


## License
[The GPLv3 license](https://www.gnu.org/licenses/gpl-3.0.en.html)


