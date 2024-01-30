use std::prelude::v1::*;

use std::collections::HashMap;

use testing::{generate_runner,test};

generate_runner!();

use super::*;

use worker_remote::*;
use 
const CONFIG: &[u8] =include_bytes!("../../testdata/config.txt");
const DS_1_BLOCK_1: &[u8] =include_bytes!("../../testdata/ds_1_block_1.txt");
const DS_1_BLOCK_2: &[u8] =include_bytes!("../../testdata/ds_1_block_2.txt");
const DS_2_BLOCK_1: &[u8] =include_bytes!("../../testdata/ds_2_block_1.txt");
const DS_2_BLOCK_2: &[u8] =include_bytes!("../../testdata/ds_2_block_2.txt");
const TEE_CONFIG: &str =include_str!("../../testdata/config.json");

#[test]
// #[should_panic(
//     expected =""error
// )]

#[test]
fn parse_argument_ok(){
    let mut ctx= fake_ctx();
    let task = &mut ctx.task;
    let args= Argument::from_dataset(&mut ctx).unwrap();

    let result: Vec<Argument> = vec![
        Argument{
             pos: 1,
             tag: 0,
             columns: vec![Column{
                name:"name".to_string,
                idx: 0,
             }] ,
        } , 
        Argument{
            pos: 2,
            tag: 1,
            columns: vec![Column{
               name:"id".to_string,
               idx: 0,
            }] ,
       } , 
    ];
    assert_eq!(args[1],result[0]);
    assert_eq!(args[2],result[1]);
}

fn fake_ctx() ->FakeContext{
    let ds1_blocks = vec![
        fake_block_with_id_only("block#1"),
        fake_block_with_id_only("block#2"),
    ];
    let ds2_blocks = vec![
        fake_block_with_id_only("block#1"),
        fake_block_with_id_only("block#2"),
    ];

    let cblocks = vec![fake_block_with_id_only("config#1")];

    let data_sets =vec! [
        fake_data_set_with_id_and_blocks_only("config#1",cblocks,10000),
        fake_data_set_with_id_and_blocks_only("data#1",ds_1_blocks,10000),
        fake_data_set_with_id_and_blocks_only("data#2",ds_2_blocks,10000),

    ];

    let task =fake_task_with_data_sets_only(data_sets,TEE_CONFIG);

    let blocks ={
        let mut blocks = HashMap::new();
        blocks.insert(
            "config#1".to_string(),
            vec![FakeBlock::new("config#1",CONFIG.to_vec())],

        );
        blocks.insert(
            "data#1".to_string(),
            vec![
                FakeBlock::new("block#1",DS_1_BLOCK_1.to_vec()),
                FakeBlock::new("block#1",DS_1_BLOCK_2.to_vec())
                ],

        );
        blocks.insert(
            "data#=2".to_string(),
            vec![
                FakeBlock::new("block#2",DS_2_BLOCK_1.to_vec()),
                FakeBlock::new("block#2",DS_2_BLOCK_2.to_vec())
                ],

        );  
        blocks
    }

    let ctx= FakeContext{
        blocks,
        outputs: vec![],
        task,
        err_write:None,
        err_read: None,
    };
    ctx
}

fn fake_block_with_id_only(block_id:&str) ->Block{
    Block{
        block_id: block_id.to_string(),
        plain_size:0,
        sha256:"".to_string(),
    }
}

fn fake_data_set_with_id_and_blocks_only(id: &str, blocks: Vec<Block>, tag: u32) -> DataSet{
    DataSet {
        dataset_id: id.to_string(),
        address: "",to_string(),
        tag: tag,
        blocks,
    }
}

fn fake_task_with_data_sets_only(data_sets: Vec<DataSet>, tee_config:& str) ->Task {
    Task {
        user_id: "".to_string(),
        task_id: "".to_string(),
        result_encryption_key: "".to_string(),
        tee_config: String::from(tee_config),
        datas: data_sets,
    }
}