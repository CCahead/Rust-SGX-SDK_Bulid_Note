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

#![crate_name = "cryptosampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
// #![cfg(target_env="sgx")]
// #![no_std] 这一行有问题！
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate libsm;
extern crate sgx_rand;
// we need  this [no_std] to activate the lazy_static features 
//instead we'll face the std conflict with sgx_tstd
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;
extern crate num_bigint;


// 
use sgx_types::*;
use sgx_tcrypto::*;
use sgx_trts::memeq::ConsttimeMemEq;
use std::vec::Vec;
use std::slice;

use std::ptr;

// use 
//New Feature
use sgx_rand::{Rng, StdRng};


use libsm::sm2::signature::{Pubkey,Seckey,Signature,SigCtx};// using libsm
use libsm::sm2::encrypt::{EncryptCtx,DecryptCtx};
use libsm::sm2::field::FieldElem;
use libsm::sm2::ecc::{Point,EccCtx};
use std::sync::SgxMutex;
use num_bigint::BigUint; // 确保引入 BigUint
lazy_static! {
    // static ref ctx: SigCtx= SigCtx::new();
    static ref SEC_KEY: SgxMutex<BigUint> = SgxMutex::new(BigUint::from(0u32));
}

// pub fn get_sk() -> BigUint {
//     let key = SEC_KEY.lock().unwrap();
//     key.clone()
// }

// pub fn set_sk(sk_tmp: BigUint) {
//     let mut key = SEC_KEY.lock().unwrap();
//     *key = sk_tmp;
// }
/// A Ecall function takes a string and output its SHA256 digest.
///
/// # Parameters
///
/// **input_str**
///
/// A raw pointer to the string to be calculated.
///
/// **some_len**
///
/// An unsigned int indicates the length of input string
///
/// **hash**
///
/// A const reference to [u8;32] array, which is the destination buffer which contains the SHA256 digest, caller allocated.
///
/// # Return value
///
/// **SGX_SUCCESS** on success. The SHA256 digest is stored in the destination buffer.
///
/// # Requirements
///
/// Caller allocates the input buffer and output buffer.
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER**
///
/// Indicates the parameter is invalid
#[no_mangle]
pub extern "C" fn calc_sha256(input_str: *const u8,
                              some_len: usize,
                              hash: &mut [u8;32]) -> sgx_status_t {

    println!("calc_sha256 invoked!");//这里不是enclave内部吗？为什么可以使用println? 而不是ocall?

    // First, build a slice for input_str
    let input_slice = unsafe { slice::from_raw_parts(input_str, some_len) };

    // slice::from_raw_parts does not guarantee the length, we need a check
    if input_slice.len() != some_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("Input string len = {}, input len = {}", input_slice.len(), some_len);

    // Second, convert the vector to a slice and calculate its SHA256
    let result = rsgx_sha256_slice(&input_slice);

    // Third, copy back the result
    match result {
        Ok(output_hash) => *hash = output_hash,
        Err(x) => return x
    }

    sgx_status_t::SGX_SUCCESS
}




// #[no_mangle]
// pub extern "C" fn DecryptMessage(&msg:u8,

//                             )-> sgx_status_t{
//     println!("Decrypting The Message!");
//     let m=0;
//     sgx_status_t::SGX_SUCCESS
// }


// #[no_mangle]
// pub extern "C" fn SigMsg(&msg:u8,

//                             )-> sgx_status_t{
//     println!("Decrypting The Message!");
//     let m=0;
//     sgx_status_t::SGX_SUCCESS
// }

// #[no_mangle]
// pub extern "C" fn VerifyMsg(&msg:u8,

//                             )-> sgx_status_t{
//     println!("Decrypting The Message!");
//     let m=0;
//     sgx_status_t::SGX_SUCCESS
// }
/// An AES-GCM-128 encrypt function sample.
///
/// # Parameters
///
/// **key**
///
/// Key used in AES encryption, typed as &[u8;16].
///
/// **plaintext**
///
/// Plain text to be encrypted.
///
/// **text_len**
///
/// Length of plain text, unsigned int.
///
/// **iv**
///
/// Initialization vector of AES encryption, typed as &[u8;12].
///
/// **ciphertext**
///
/// A pointer to destination ciphertext buffer.
///
/// **mac**
///
/// A pointer to destination mac buffer, typed as &mut [u8;16].
///
/// # Return value
///
/// **SGX_SUCCESS** on success
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER** Indicates the parameter is invalid.
///
/// **SGX_ERROR_UNEXPECTED** Indicates that encryption failed.
///
/// # Requirements
///
/// The caller should allocate the ciphertext buffer. This buffer should be
/// at least same length as plaintext buffer. The caller should allocate the
/// mac buffer, at least 16 bytes.
#[no_mangle]
pub extern "C" fn aes_gcm_128_encrypt(key: &[u8;16],
                                      plaintext: *const u8,
                                      text_len: usize,
                                      iv: &[u8;12],
                                      ciphertext: *mut u8,
                                      mac: &mut [u8;16]) -> sgx_status_t {

    println!("aes_gcm_128_encrypt invoked!");

    // First, we need slices for input
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, text_len) };

    // Here we need to initiate the ciphertext buffer, though nothing in it.
    // Thus show the length of ciphertext buffer is equal to plaintext buffer.
    // If not, the length of ciphertext_vec will be 0, which leads to argument
    // illegal.
    let mut ciphertext_vec: Vec<u8> = vec![0; text_len];

    // Second, for data with known length, we use array with fixed length.
    // Here we cannot use slice::from_raw_parts because it provides &[u8]
    // instead of &[u8,16].
    let aad_array: [u8; 0] = [0; 0];
    let mut mac_array: [u8; SGX_AESGCM_MAC_SIZE] = [0; SGX_AESGCM_MAC_SIZE];

    // Always check the length after slice::from_raw_parts
    if plaintext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let ciphertext_slice = &mut ciphertext_vec[..];
    println!("aes_gcm_128_encrypt parameter prepared! {}, {}",
              plaintext_slice.len(),
              ciphertext_slice.len());

    // After everything has been set, call API
    let result = rsgx_rijndael128GCM_encrypt(key,
                                             &plaintext_slice,
                                             iv,
                                             &aad_array,
                                             ciphertext_slice,
                                             &mut mac_array);
    println!("rsgx calling returned!");

    // Match the result and copy result back to normal world.
    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => {
            unsafe{
                ptr::copy_nonoverlapping(ciphertext_slice.as_ptr(),
                                         ciphertext,
                                         text_len);
            }
            *mac = mac_array;
        }
    }

    sgx_status_t::SGX_SUCCESS
}

/// An AES-GCM-128 decrypt function sample.
///
/// # Parameters
///
/// **key**
///
/// Key used in AES encryption, typed as &[u8;16].
///
/// **ciphertext**
///
/// Cipher text to be encrypted.
///
/// **text_len**
///
/// Length of cipher text.
///
/// **iv**
///
/// Initialization vector of AES encryption, typed as &[u8;12].
///
/// **mac**
///
/// A pointer to source mac buffer, typed as &[u8;16].
///
/// **plaintext**
///
/// A pointer to destination plaintext buffer.
///
/// # Return value
///
/// **SGX_SUCCESS** on success
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER** Indicates the parameter is invalid.
///
/// **SGX_ERROR_UNEXPECTED** means that decryption failed.
///
/// # Requirements
//
/// The caller should allocate the plaintext buffer. This buffer should be
/// at least same length as ciphertext buffer.
#[no_mangle]
pub extern "C" fn aes_gcm_128_decrypt(key: &[u8;16],
                                      ciphertext: *const u8,
                                      text_len: usize,
                                      iv: &[u8;12],
                                      mac: &[u8;16],
                                      plaintext: *mut u8) -> sgx_status_t {

    println!("aes_gcm_128_decrypt invoked!");

    // First, for data with unknown length, we use vector as builder.
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, text_len) };
    let mut plaintext_vec: Vec<u8> = vec![0; text_len];

    // Second, for data with known length, we use array with fixed length.
    let aad_array: [u8; 0] = [0; 0];

    if ciphertext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let plaintext_slice = &mut plaintext_vec[..];
    println!("aes_gcm_128_decrypt parameter prepared! {}, {}",
              ciphertext_slice.len(),
              plaintext_slice.len());

    // After everything has been set, call API
    let result = rsgx_rijndael128GCM_decrypt(key,
                                             &ciphertext_slice,
                                             iv,
                                             &aad_array,
                                             mac,
                                             plaintext_slice);

    println!("rsgx calling returned!");

    // Match the result and copy result back to normal world.
    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => {
            unsafe {
                ptr::copy_nonoverlapping(plaintext_slice.as_ptr(),
                                         plaintext,
                                         text_len);
            }
        }
    }

    sgx_status_t::SGX_SUCCESS
}

/// A sample aes-cmac function.
///
/// # Parameters
///
/// **text**
///
/// The text message to be calculated.
///
/// **text_len**
///
/// An unsigned int indicate the length of input text message.
///
/// **key**
///
/// The key used in AES-CMAC, 16 bytes sized.
///
/// **cmac**
///
/// The output buffer, at least 16 bytes available.
///
/// # Return value
///
/// **SGX_SUCCESS** on success.
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER** indicates invalid input parameters
///
/// # Requirement
///
/// The caller should allocate the output cmac buffer.
#[no_mangle]
pub extern "C" fn aes_cmac(text: *const u8,
                           text_len: usize,
                           key: &[u8;16],
                           cmac: &mut [u8;16]) -> sgx_status_t {

    let text_slice = unsafe { slice::from_raw_parts(text, text_len) };

    if text_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let result = rsgx_rijndael128_cmac_slice(key, &text_slice);

    match result {
        Err(x) => return x,
        Ok(m) => *cmac = m
    }

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn rsa_key(text: * const u8, text_len: usize) -> sgx_status_t {

    let text_slice = unsafe { slice::from_raw_parts(text, text_len) };

    if text_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let mod_size: i32 = 256;
    let exp_size: i32 = 4;
    let mut n: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut d: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut e: Vec<u8> = vec![1, 0, 1, 0];
    let mut p: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut q: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmp1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmq1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut iqmp: Vec<u8> = vec![0_u8; mod_size as usize / 2];

    let result = rsgx_create_rsa_key_pair(mod_size,
                                          exp_size,
                                          n.as_mut_slice(),
                                          d.as_mut_slice(),
                                          e.as_mut_slice(),
                                          p.as_mut_slice(),
                                          q.as_mut_slice(),
                                          dmp1.as_mut_slice(),
                                          dmq1.as_mut_slice(),
                                          iqmp.as_mut_slice());

    match result {
        Err(x) => {
            return x;
        },
        Ok(()) => {},
    }

    let privkey = SgxRsaPrivKey::new();
    let pubkey = SgxRsaPubKey::new();

    let result = pubkey.create(mod_size,
                               exp_size,
                               n.as_slice(),
                               e.as_slice());
    match result {
        Err(x) => return x,
        Ok(()) => {},
    };

    let result = privkey.create(mod_size,
                                exp_size,
                                e.as_slice(),
                                p.as_slice(),
                                q.as_slice(),
                                dmp1.as_slice(),
                                dmq1.as_slice(),
                                iqmp.as_slice());
    match result {
        Err(x) => return x,
        Ok(()) => {},
    };

    let mut ciphertext: Vec<u8> = vec![0_u8; 256];
    let mut chipertext_len: usize = ciphertext.len();
    let ret = pubkey.encrypt_sha256(ciphertext.as_mut_slice(),
                                    &mut chipertext_len,
                                    text_slice);
    match ret {
        Err(x) => {
            return x;
        },
        Ok(()) => {
            println!("rsa chipertext_len: {:?}", chipertext_len);
        },
    };

    let mut plaintext: Vec<u8> = vec![0_u8; 256];
    let mut plaintext_len: usize = plaintext.len();
    let ret = privkey.decrypt_sha256(plaintext.as_mut_slice(),
                                     &mut plaintext_len,
                                     ciphertext.as_slice());
    match ret {
        Err(x) => {
            return x;
        },
        Ok(()) => {
            println!("rsa plaintext_len: {:?}", plaintext_len);
        },
    };

    if plaintext[..plaintext_len].consttime_memeq(text_slice) == false {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    sgx_status_t::SGX_SUCCESS
}



#[no_mangle]
// My Sample Using SM2 Ecall Generating the PubKey 
// 问题：对象生存期？这个ctx椭圆曲线，以及这个秘钥肯定是要跟着enclave的生命周期同步的吧
pub extern "C" fn GeneratePubKey(
                           pubkey: *mut u8// not &mut
                       ) -> sgx_status_t{
    let ctx: SigCtx= SigCtx::new();
    // println!("Generating the Public Key!");
    // let keypair_result=ctx.new_keypair();
    // println!("test1");

    let (pub_key,sec_key)= match ctx.new_keypair(){
        
        Ok((pub_key,sec_key)) => {
            (pub_key, sec_key)
        }
        Err(e) =>{
            println!("生成密钥对出错:{}",e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;//是否是这样写？
            // ocall 
        }
    };
    // let mut count=0;
    // println!("The x is :");
    // while count<=7{
    //     println!("{}", Pub_Key.x.get_value(count));
    //     count+=1;
    // }
    // println!("\n");
    // count=0;
    // let mut x_outstr=Pub_Key.x.to_bytes();
    // let res=FieldElem::from_bytes(&x_outstr);
    // let mut x_label: FieldElem;
    // let mut y_label: FieldElem;
    // match res{
    //     Ok(xlab) => 
    //     {
    //         x_label=xlab;
    //     },
    //     Err(e) =>{
    //         println!("error {}",e);
    //         return sgx_status_t::SGX_ERROR_UNEXPECTED;
    //     } 
    // }
    // println!("The pk:x is {:#?}\n",x_label);
    println!("The key pair is: pk:{}, sk:{}",pub_key,sec_key);
    unsafe{
        let mut tmp=SEC_KEY.lock().unwrap();
        * tmp=sec_key;
    }//update the static SEC_KEY
    let mut key_vec=match ctx.serialize_pubkey(&pub_key,false){
        Ok(res) => {
            res
        }
        Err(e) =>{
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    
    // 
    // let mut y_vec=Pub_Key.y.to_bytes(); // it should be mut ? why : could not borrow!
    
    let key_vec_slice = &mut key_vec[..];
    // let y_vec_slice = &mut y_vec[..];

    unsafe{
        ptr::copy_nonoverlapping(
            key_vec_slice.as_ptr(),
            pubkey,
            65// or len?
        );
    }
    // let X:libsm::sm2::field::FieldElem=Pub_Key.x.clone();
    // let Y:libsm::sm2::field::FieldElem=Pub_Key.y.clone();    // set_sec_key(sec_key);// set Sec_Key
    // println!("The key pair is: pk:{}, sk:{}",X,Y);
    //要传参出来吧？ 先要确定这个key-pair的数据格式
    // 一般ecall都是以引用格式传回参数，所以肯定要先确定传参嘛
    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn EncryptMessage(
                            pk_key: & [u8;65], // it's static  刚才这里没有加&引用，就一直报错！invalid pk!
                            plaintext: *const u8, //it's dynamic ? so use *?
                            plaintext_len: usize,
                            ciphertext: *mut u8,
                            cipher_len: usize
                            )-> sgx_status_t{
    // init encrypt unit
    // let ctx = match EncryptCtx::load_pubkey(&pk_key){
    //     Ok(res)=> {
    //         sgx_status_t::SGX_SUCCESS
    //     }
    //     Err(e)=>return sgx_status_t::SGX_ERROR_UNEXPECTED,
    // };
    
    let curve = EccCtx::new();
    let ctx = SigCtx::new();
    let pk =  ctx.load_pubkey(&pk_key[..]).unwrap();

    let text_slice = unsafe { slice::from_raw_parts(plaintext,plaintext_len) };
    if text_slice.len() != plaintext_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let encrypt_ctx=EncryptCtx::new(plaintext_len,pk);
    let mut cipher=encrypt_ctx.encrypt(text_slice).unwrap();


    let cipher_slice = &mut cipher[..];

    unsafe{
        ptr::copy_nonoverlapping(
            cipher_slice.as_ptr(),
            ciphertext,
            cipher_len// or len?
        );
    }
    println!("Encrypting The Message!");


    println!("\n");    println!("pk:{}",pk);

    println!("Encrypting The Message!");

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn DecryptMessage(
    ciphertext: *const u8, //it's dynamic ? so use *?
    cipher_len: usize,
    plaintext: *mut u8,
    plaintext_len: usize
    )-> sgx_status_t{
        println!("Decrypting The Message!");
        let curve = EccCtx::new();

        let sk_guard = SEC_KEY.lock().unwrap();

        println!("sk:{}",sk_guard);
        let decrypt_ctx = DecryptCtx::new(plaintext_len.clone(),sk_guard.clone());
        
        let text_slice = unsafe { slice::from_raw_parts(ciphertext,cipher_len) };

        if text_slice.len() != cipher_len {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
        
        let mut plain_text=decrypt_ctx.decrypt(text_slice).unwrap();
    
        // println!("{}",plain_text.clone());
        let plain_slice = &mut plain_text[..];
    
        unsafe{
            ptr::copy_nonoverlapping(
                plain_slice.as_ptr(),
                plaintext,
                plaintext_len// or len?
            );
        }    
        sgx_status_t::SGX_SUCCESS

    }

    #[no_mangle]

pub  extern "C" fn encry(

     plaintext :  * const u8,
     plain_len :  usize ,
     ciphertext : * mut u8 ,
     cipher_len :  usize  
) ->sgx_status_t {

    let ctx=SigCtx::new();

    let (pk,sk)= ctx.new_keypair().unwrap();

    let encrypt_ctx = EncryptCtx::new(plain_len, pk);

let text_slice = unsafe { slice::from_raw_parts(plaintext,plain_len) };
if text_slice.len() != plain_len {
    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
}

let mut cipher=encrypt_ctx.encrypt(text_slice).unwrap();


let cipher_slice = &mut cipher[..];

unsafe{
    ptr::copy_nonoverlapping(
        cipher_slice.as_ptr(),
        ciphertext,
        cipher_len// or len?
    );
}
    sgx_status_t::SGX_SUCCESS
}