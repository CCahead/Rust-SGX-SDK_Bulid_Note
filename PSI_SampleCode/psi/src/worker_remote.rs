use serde::{Deserialize,Serialize};
use std::io::{self,Read,Error};
use std::fs::File;
use std::path::Path;
use std::vec::Vec;
pub type Result<T> = std::result::Result<T,Error>;//这是一种简化版本的定义返回值的方法，这里就只是用了Result<T>来表示，省去了写error的麻烦
#[derive(Serialize,Deserialize,Debug)]
pub struct Block {
    pub block_id: String,
    pub plain_size: u64,
    pub sha256:String,
}

#[derive(Serialize,Deserialize,Debug)]
pub struct DataSet {
    pub dataset_id:String,
    pub address:String, //tdfs
    pub tag: u32,
    pub blocks: Vec<Block>,
}


// pub struct Error{
//    err:String,
// }

// pub struct Result{
//     res: String,
// }

pub trait Context{
    fn read_block(&self,dataset_id: &str, block_id:&str) ->
    Result<Vec<u8>>;

    fn write_file(&mut self, desc:&str,data:&[u8])->
    Result<()>;
    // Result<()>

    fn dataset_by_tag(&self,tag:u32)->
    Vec<DataSet>;


}

pub trait Worker{
    fn execute(&mut self, ctx:&mut dyn Context)->Result<String>;//Result<String>
}

pub struct Ctx{
}

impl Context for Ctx{
    fn read_block(&self,dataset_id: &str, block_id:&str) ->
    Result<Vec<u8>>
    // Result<Vec<u8>>
    {
        //这里的逻辑有问题 需要再修改
        let mut file_path=String::from("");
        let path = Path::new(&file_path);
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)

    }
    fn write_file(&mut self, desc:&str,data:&[u8])->
    Result<()>
    // Result<()>
    {
        Ok(())
    }
    fn dataset_by_tag(&self,tag:u32)->
    Vec<DataSet>
    // Vec<Dataset>
    {
        let mut datasets = Vec::new();

        let dataset = DataSet {
            dataset_id: "1".to_string(),
            address: "tdfs1".to_string(),
            tag: 1,
            blocks: vec![/* 初始化 blocks */],
        };
    
        datasets.push(dataset);
    
        // 根据需要创建更多 DataSet 实例并添加到向量中
    
        datasets
    }
}