

// #extern crate serde_derive;
use std::vec::Vec;
use std::iter::Iterator;
use std::io::{self,BufRead,Error,ErrorKind};
pub type Result<T> = std::result::Result<T,Error>;//这是一种简化版本的定义返回值的方法，这里就只是用了Result<T>来表示，省去了写error的麻烦
use std::string::ToString;
use std::io::Cursor;
use std::slice;
use std::collections::HashMap;
use serde::{Deserialize,Serialize};



use crate::argument::{Argument,Column};
use crate::worker_remote::{Context,Worker,DataSet};


pub struct PSI{}

#[derive(Serialize,Deserialize,Debug)]
pub struct DataSetReport{
    pub id:String,
    pub tag:u32,
    pub columns :Vec<String>,
    pub rows: u32,
    pub missing: u32,
}


#[derive(Serialize,Deserialize,Debug)]
pub struct PSIReport{
    #[serde(skip)]
    pub map:HashMap<String,u32>,
    pub size: u32,
    pub dataset: Vec<DataSetReport>,
}

impl ToString for PSIReport{
    fn to_string(&self) ->String{
        let mut out=String::new();
        out.push_str(format!("dataset intersection size:{}\n", self.size).as_str());
        out.push_str("dataset    tag    rows   columns   missing");
        for dsr in &self.dataset{
            out.push_str(
                format!(
                    "{} {} {} {} {}\n",
                    &dsr.id,
                    dsr.tag,
                    dsr.rows,
                    dsr.columns.join(","),
                    dsr.missing
                )
                .as_str(),
            );
        }
        return out;
    }
}


impl PSI{
    fn validate_args(&mut self, args: &Vec<Argument>)-> bool {
        if args.len()==0{
            println!("error1");
            return false;
        }


        let base=args[1].columns.len();
        for i in 1..args.len(){
            if args[i].columns.len() !=base {
                println!("error2");
                return false;
            }
        }
        println!("ok");
        return true;
    }




    fn psi_read_columns(
        &self,
        ctx: &mut dyn Context,
        dataset: &DataSet,
        cols: &Vec<Column>,
        report: &mut PSIReport,
    )->Result<()>{
        let mut pos=0;
        let mut header_idx: Vec<u8> = Vec::new();
        
        let mut dsr = DataSetReport {
            id: String::from(&dataset.dataset_id),
            tag: dataset.tag,
            rows: 0,
            columns: Vec::new(),
            missing: 0,
        };
        
        for col in cols{
            dsr.columns.push(String::from(&col.name));
        }

        for b in &dataset.blocks{
            let mut cursor = ctx
                .read_block(&dataset.dataset_id,&b.block_id)
                // .map_err(|err|{
                //     //这里他们是自定义了一个Error::new_...我在这里把它改成标准Error
                //     Error::new(
                //         ErrorKind::Other, 
                //         format!("error: failed to read block {} and dataset {}: {}", b.block_id, dataset.dataset_id, err)
                //     )
                // })
                .map(|v| String::from_utf8(v).unwrap())
                .map(io::Cursor::new)?; //这里由于之前这个函数的返回值是写的() 导致这里在使用()?;的时候一直报错！查阅
                //https://stackoverflow.com/questions/52225498/strange-error-cannot-use-the-operator-in-a-function-that-returns才找到问题
            if pos == 0{
                //read the dataset header
                let mut headerline = String::new();
                // if let Err(err) = cursor.read_line(&mut headerline){
                //     return Err(Error::new(
                //         ErrorKind::Other, 
                //         format!("error:fail to read header line of dataset{} :{}", dataset.dataset_id, err
                //     )));
                //     // println!("error:fail to read header line of dataset");
                    
                //     // return ;
                // }
                let parts = headerline
                    .as_str()
                    .split(",")
                    .map(|v| v.trim())
                    .collect::<Vec<_>>();
                //这个步骤应该就是求交步骤
                for c in cols{
                    for i in 0..parts.len(){
                        if c.name == parts[i]{
                            header_idx.push(i as u8);
                        }
                    }
                }
                //求交

                if header_idx.len() != cols.len(){
                    // return 
                    // Err(Error::new(format!(
                    //     "dataset has no enough col"
                    //         )));
                    println!("dataset has no enough col");
                    return Ok(());
                }
                pos+=1;
            }
            cursor
                .lines()
                .map(|line|{
                    match line {
                        // Err(err) => {
                        //     return Err(Error::new(err));
                        Err(err)=>{
                            println!("for loop: cursor read line err");
                            return ;
                        }
                        Ok(s) => {
                            let parts = s.as_str().split(",").map(|v| v.trim()).collect::<Vec<_>>();//为什么这么写？
                            //this is the data
                            let mut content = String::new();
                            let mut ok =true;
                            for idx in &header_idx {
                                if parts.len() <= *idx as usize {
                                    //data field empty
                                    dsr.missing +=1;
                                    ok =false;
                                    break;
                                }
                                if parts[*idx as usize] == ""{
                                    dsr.missing +=1;
                                    ok =false;
                                    break;
                                }
                                content.push_str(parts[*idx as usize]);
                            }
                            if ok {
                                *report.map.entry(content).or_insert(0) +=1;
                            }
                        }//ok
                    }//match line 

                    pos +=1;
                    ()
                })//map
                .for_each(drop);
            }//for block loop
            dsr.rows = pos -1;
            report.dataset.push(dsr);
            Ok(())
    }
    fn psi_add_dataset(
        &mut self,
        ctx: &mut dyn Context,
        arg: &Argument,
        report: &mut PSIReport,
    ) ->Result<()>{
        let datas = ctx.dataset_by_tag(arg.tag as u32);
        if datas.len() ==0 {
            println!("dataset with the selected tag not found");
            return Ok(());
        }
        if datas.len() != 1{
            println!("too many datasets have the same tag");
            return Ok(());
        }
        return self.psi_read_columns(ctx,&datas[0],&arg.columns,report);
    }

    // fn psi_summary(&mut self, ctx:&mut dyn Context, repot: &mut PSIReport) ->() {
    //     // let thres =ctx.tas
    //     // Ok(())
    //     ()
    // }
}



impl Worker for PSI{
    // fn function_name (&self) -> &str{
    //      "psi"
    // }

    fn execute(&mut self, ctx:&mut dyn Context) -> Result<String> {
        // match Argument::from_tee_config(ctx) {
        //     Ok(args) => {
        //         self.validate_args(&args);
        //     }
        // }
        Ok(String::from("test"))
    }
}


