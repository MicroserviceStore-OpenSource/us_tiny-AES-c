# kokke's tiny-AES-c as embedded Microservice

## How to build
1. Download the tiny-AES-c tested version/SHA. (Please see Libs/libraries.txt for the latest tested SHA)
    > make init_repo

2. We have some minor changes on the tiny-AES-c repository, to enable/disable some AES modes and key lengths using compiler switches. In this way, we can optimise the memory footprint. Herein, please apply the patch under Libs/ folder.

    > cd Libs/tiny-AES-c

    > git am ../0001-Microservice-Store-Changes-Enable-192-and-256-Bit-Ke.patch

3. We have created an example config file, that supports only AES-CBC for 256Bit Key lengths. See Configurations/CortexM4_CBC_256.config. <br>

    ```makefile
    uSERVICE_CFLAGS= \
        -O \
        -DECB=0 -DCTR=0 -DCBC=1 \
        -DAES128=0 -DAES192=0 -DAES256=1
    ```

    You can create your own configs and optimised microservices to support other functions in the tiny-AES-c.

4. Just generate a package for a specific config by running running the following command in the root directory.
    > make package CONFIG=CortexM4_CBC_256


If you want to see the "How to Implement an embedded Microservice", please see  [Microservice Template Project](https://github.com/MicroserviceStore/us-Template-C/blob/main/README.md)

