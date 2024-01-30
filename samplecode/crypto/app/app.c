// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "app.h"
#include "Enclave_u.h"


sgx_enclave_id_t global_eid = 0;
typedef struct PublicKey{
    uint8_t key[65];
    // uint8_t y[32];
} PK;
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};




/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

int initialize_enclave(void)
{
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    printf("[+] global_eid: %ld\n", global_eid);
    return 0;
}
int test(){
        sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_status_t enclave_ret = SGX_SUCCESS;
    uint32_t sealed_log_size = 1024;
    uint8_t sealed_log[1024] = {0};
     int i=0;
    const char * text="helloworld";
    uint8_t text_len= strlen(text);
    printf("%d",text_len);
    uint8_t ciph_len= 65+32+text_len;
        uint8_t* cipher = (uint8_t*)malloc(ciph_len);

    sgx_ret =  encry(global_eid,&enclave_ret,(const uint8_t *) text, text_len, cipher,ciph_len);
    if(sgx_ret != SGX_SUCCESS) {
        print_error_message(sgx_ret);
        return -1;
    }

    if(enclave_ret != SGX_SUCCESS) {
        print_error_message(enclave_ret);
        return -1;
    }
   printf("[+] The ciphertest is \n");
    for(i ; i <= ciph_len-1; i ++) {
        printf("%02x", cipher[i]);
    }
    printf("\n");
}
/* Application entry */
int GeneratePubKey_test(PK* pk){
            sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_status_t enclave_ret = SGX_SUCCESS;
    uint32_t sealed_log_size = 1024;
    uint8_t sealed_log[1024] = {0};
    int i=0;
    sgx_ret = GeneratePubKey(global_eid,
                         &enclave_ret,
                         pk->key
                         );

    if(sgx_ret != SGX_SUCCESS) {
        print_error_message(sgx_ret);
        return -1;
    }

    if(enclave_ret != SGX_SUCCESS) {
        print_error_message(enclave_ret);
        return -1;
    }

    printf("[+] SM2 Public Key Sery is ");

    for(i = 0; i <= 64; i ++) {
        printf("%02x", pk->key[i]);
    }
    printf("\n");


    printf("\n");  
    printf("[+] GeneratePubKey success ...\n");
}

int EncryptMessageTest(PK* pk,const char* plain_text,uint8_t** cipher_text,uint8_t* cipher_len){
        sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_status_t enclave_ret = SGX_SUCCESS;
    uint32_t sealed_log_size = 1024;
    uint8_t sealed_log[1024] = {0};
    uint8_t plain_len = strlen(plain_text);
    
    // uint8_t ciph_text
    uint8_t ciph_len=65+plain_len+32;
    uint8_t*  cipher_text_tmp = (uint8_t*)malloc(ciph_len);  

    sgx_ret = EncryptMessage(global_eid,
                         &enclave_ret,
                         pk->key,
                        (const uint8_t *) plain_text,
                         plain_len,
                         cipher_text_tmp,
                         ciph_len
                         );
    *cipher_text=cipher_text_tmp;
    int i=0;
    *cipher_len=ciph_len;
    // printf("[+] %d\n",ciph_len);
    // printf("[+] The cipher_len  is \n");
    // for (i=0;i<=ciph_len-1;i++){
    //     printf("%02x", cipher_text_tmp[i]);
    // }
    return 0;
}
int DecryptMessageTest(const uint8_t *cipher_text,uint8_t cipher_len,uint8_t** plain_text1,uint8_t plain_len1){
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_status_t enclave_ret = SGX_SUCCESS;
    uint32_t sealed_log_size = 1024;
    uint8_t sealed_log[1024] = {0};
    
    uint8_t* tmp= (uint8_t*)malloc(plain_len1);

    sgx_ret = DecryptMessage(global_eid,
                             &enclave_ret,
                             (const uint8_t *) cipher_text,
                             cipher_len,
                             tmp,
                             plain_len1
                               );

    *plain_text1=tmp;
}
int SGX_CDECL main(int argc, char *argv[])
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_status_t enclave_ret = SGX_SUCCESS;
    uint32_t sealed_log_size = 1024;
    uint8_t sealed_log[1024] = {0};

    (void)(argc);
    (void)(argv);
    int i=0;
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }


    int te=test();
    PK*  pk= (PK*)malloc(sizeof(PK)); 



    int res_GeneratePubKey_test=GeneratePubKey_test(pk);

    const char* plain_text= "helloworld";
    uint8_t* cipher_text = NULL;    // 一个指向 uint8_t 的指针，用于指向加密数据
    uint8_t cipher_len = 0; 

    int res_EncryptMessage_test=EncryptMessageTest(pk,plain_text,&cipher_text,&cipher_len);
    printf("[+] res_EncryptMessage_test:%d\n",res_EncryptMessage_test);

    printf("[+] %d\n",cipher_len);
    printf("[+] The cipher_len  is \n");
    for (i=0;i<=cipher_len-1;i++){
        printf("%02x", cipher_text[i]);
    }

    //test:Decrypt
    uint8_t plain_len1=cipher_len-65-32;
    uint8_t* plain_text1=NULL;
    int res_DecryptMessage_test=DecryptMessageTest(cipher_text,cipher_len,&plain_text1,plain_len1);

    printf("[+] res_DecryptMessage_test%d\n",res_DecryptMessage_test);
    printf("[+] %d\n",plain_len1);
    printf("[+] The plain_text1  is \n");
    for (i=0;i<=plain_len1-1;i++){
        // printf("1");
        printf("%c", plain_text1[i]);
    }
    printf("\n");
    // libsm test case
    // edit by junjun
    // TEST1





//     printf("[+] The cipher is \n");
//     for(i = 0; i <=ciph_len -1; i ++) {
//         printf("%02x", ciph_text[i]);
//     }
//     printf("\n");
    
//     uint8_t * plain1;
    






    // SHA-256 test case comes from
    // https://tools.ietf.org/html/rfc4634
    // TEST1
    // const char* str = "abc";
    // size_t len = strlen(str);
    // uint8_t * output_hash = (uint8_t *) malloc (32 + 1);

    // printf("[+] sha256 input string is %s\n", str);
    // printf("[+] Expected SHA256 hash: %s\n",
    //        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // sgx_ret = calc_sha256(global_eid,
    //                      &enclave_ret,
    //                      (const uint8_t *) str,
    //                      len,
    //                      output_hash);

    // if(sgx_ret != SGX_SUCCESS) {
    //     print_error_message(sgx_ret);
    //     return -1;
    // }

    // if(enclave_ret != SGX_SUCCESS) {
    //     print_error_message(enclave_ret);
    //     return -1;
    // }

    // printf("[+] SHA256 result is ");

    // // int i;
    // for(i = 0; i < 32; i ++) {
    //     printf("%02x", output_hash[i]);
    // }
    // printf("\n");
    // printf("[+] calc_sha256 success ...\n");

    // // AES-GCM-128 test case comes from
    // // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
    // // Test case 2

    // printf("[+] Starting aes-gcm-128 encrypt calculation\n");
    // uint8_t aes_gcm_plaintext[16] = {0};
    // uint8_t aes_gcm_key[16] = {0};
    // uint8_t aes_gcm_iv[12] = {0};
    // uint8_t aes_gcm_ciphertext[16] = {0};
    // uint8_t aes_gcm_mac[16] = {0};

    // printf("[+] aes-gcm-128 args prepared!\n");
    // printf("[+] aes-gcm-128 expected ciphertext: %s\n",
    //        "0388dace60b6a392f328c2b971b2fe78");
    // sgx_ret = aes_gcm_128_encrypt(global_eid,
    //                               &enclave_ret,
    //                               aes_gcm_key,
    //                               aes_gcm_plaintext,
    //                               16,
    //                               aes_gcm_iv,
    //                               aes_gcm_ciphertext,
    //                               aes_gcm_mac);

    // printf("[+] aes-gcm-128 returned from enclave!\n");

    // if(sgx_ret != SGX_SUCCESS) {
    //     print_error_message(sgx_ret);
    //     return -1;
    // }

    // if(enclave_ret != SGX_SUCCESS) {
    //     print_error_message(enclave_ret);
    //     return -1;
    // }

    // printf("[+] aes-gcm-128 ciphertext is: ");
    // for(i = 0; i < 16; i ++) {
    //     printf("%02x", aes_gcm_ciphertext[i]);
    // }
    // printf("\n");

    // printf("[+] aes-gcm-128 result mac is: ");
    // for(i = 0; i < 16; i ++) {
    //     printf("%02x", aes_gcm_mac[i]);
    // }
    // printf("\n");

    // printf("[+] Starting aes-gcm-128 decrypt calculation\n");
    // printf("[+] aes-gcm-128 expected plaintext:");
    // for(i = 0; i < 16; i ++) {
    //     printf("%02x", aes_gcm_plaintext[i]);
    // }
    // printf("\n");

    // uint8_t aes_gcm_decrypted_text[16] = {0};
    // sgx_ret = aes_gcm_128_decrypt(global_eid,
    //                               &enclave_ret,
    //                               aes_gcm_key,
    //                               aes_gcm_ciphertext,
    //                               16,
    //                               aes_gcm_iv,
    //                               aes_gcm_mac,
    //                               aes_gcm_decrypted_text);

    // if(sgx_ret != SGX_SUCCESS) {
    //     print_error_message(sgx_ret);
    //     return -1;
    // }
    // if(enclave_ret != SGX_SUCCESS) {
    //     print_error_message(enclave_ret);
    //     return -1;
    // }

    // printf("[+] aes-gcm-128 decrypted plaintext is: ");
    // for(i = 0; i < 16; i ++) {
    //     printf("%02x", aes_gcm_decrypted_text[i]);
    // }
    // printf("\n");

    // printf("[+] aes-gcm-128 decrypt complete \n");

    // // AES-CMAC test case comes from
    // // https://tools.ietf.org/html/rfc4493
    // // Example 3

    // printf("[+] Starting aes-cmac test \n");
    // printf("[+] aes-cmac expected digest: %s\n",
    //        "51f0bebf7e3b9d92fc49741779363cfe");

    // uint8_t cmac_key[] = {
	// 	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    //     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	// };

	// uint8_t cmac_msg[] = {
    //     0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    //     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    //     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    //     0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    //     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    //     0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    //     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    //     0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    // };

    // uint8_t cmac_result[16] = {0};

    // sgx_ret = aes_cmac(global_eid,
    //                    &enclave_ret,
    //                    cmac_msg,
    //                    sizeof(cmac_msg),
    //                    cmac_key,
    //                    cmac_result);

    // if(sgx_ret != SGX_SUCCESS) {
    //     print_error_message(sgx_ret);
    //     return -1;
    // }
    // if(enclave_ret != SGX_SUCCESS) {
    //     print_error_message(enclave_ret);
    //     return -1;
    // }

    // printf("[+] aes-cmac result is: ");
    // for(i = 0; i < 16; i ++){
    //     printf("%02x", cmac_result[i]);
    // }
    // printf("\n");

    // uint8_t rsa_msg[] = {
    //     0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    //     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    //     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    //     0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    //     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    //     0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    //     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    //     0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    //     0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    //     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    //     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    //     0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    //     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    //     0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    //     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    //     0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    // };

    // sgx_ret = rsa_key(global_eid,
    //                   &enclave_ret,
    //                   rsa_msg,
    //                   sizeof(rsa_msg));

    // if(sgx_ret != SGX_SUCCESS) {
    //     print_error_message(sgx_ret);
    //     return -1;
    // }
    // if(enclave_ret != SGX_SUCCESS) {
    //     print_error_message(enclave_ret);
    //     return -1;
    // }
    // printf("rsa_key success. \n");

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}
