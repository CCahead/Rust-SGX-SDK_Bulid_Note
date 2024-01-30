// use psi::worker_remote::{Worker,Context,Ctx};
// use psi::worker::{PSI};
use std::env;
use std::fs;
use std::string::String;
use std::vec::Vec;
use std::io::{self,BufRead,BufReader,Cursor,Error,ErrorKind};
use std::collections::HashMap;
// use std::io;
// use std::collections::HashMap;
pub struct t{
    pub id:u8,
}
pub struct report{
    pub res:Vec<t>,
}
fn print_hashmap(hashmap: &HashMap<String, u32>) {
    for (key, value) in hashmap.iter() {
        println!("{}: {}", key, value);
    }
}




fn test( hashmap: &mut HashMap<String,u32> , block1_1_path: &str) -> io::Result<()> {
    let mut temp_map:HashMap<String,bool> = HashMap::new();//新建一个hashmap
    // let block1_1_path = String::from("testdata/d1_block1.txt");
    // let block1_2_path = String::from("testdata/d1_block2.txt");

    println!("in file:{}",block1_1_path);
    // let block_1_1_content = fs::read_to_string(block1_1_path)?; this is a String
    let mut cursor = fs::read(block1_1_path)
        .map(|v| String::from_utf8(v).unwrap())
        .map(Cursor::new)?; //this cursor is  Vec<u8> type.

    // let mut cursor = Cursor::new(block_1_1_content);

    let mut cols = Vec::new();
    cols.push("name".to_string());
    cols.push("gender".to_string());
    
    let mut pos = 0;
    let mut header_idx: Vec<u8> = Vec::new();
    if pos == 0 {
        let mut headerline = String::new();
        cursor.read_line(&mut headerline);
        let parts = headerline
            .as_str()
            .split(",")
            .map(|v| v.trim())
            .collect::<Vec<_>>();
        for c in cols {
            for i in 0..parts.len(){// in for loop: it's 0..parts.len()
                if parts[i] == c{
                    header_idx.push(i as u8);
                }

            }
        }           
    } 
    for idx in &header_idx {
        
    }
    cursor
        .lines()
        .map(|line|{
            match line {
                Err(err)=>{
                    return (())
                            }
           Ok(s)=>{
            let parts = s.as_str().split(",").map(|v| v.trim()).collect::<Vec<_>>();//为什么这么写？
            let mut content = String::new();
            let mut ok = true;
            for idx in &header_idx{
                if parts.len() <= *idx as usize {
                    //data field empty
                    println!("missing+1\n"); 
                    ok =false;
                    break;
                }   
                if parts[*idx as usize] == ""{
                    println!("missing+1\n"); 
                    ok =false;
                    break;
                }
                content.push_str(parts[*idx as usize]);           
                }//for header_idx
                if ok{
                    if !temp_map.contains_key(&content) {
                        * hashmap.entry(content.clone()).or_insert(0)+=1;
                        temp_map.insert(content, true); // 标记为已出现
                    }
                //    * hashmap.entry(content).or_insert(0)+=1;
                }
            }//ok
        }//match line 
        pos +=1;// row ++
        () //return a result
    })
    .for_each(drop);
        // println!("Line:{}", line);
    
    // println!("{}",block_1_1_content);
    print_hashmap(&hashmap);
    println!("The dataset has: {} rows\n",pos);
    // println!(");
    // let block_1_2_content = fs::read_to_string(block1_2_path)
    //     .expect("...");
    
    // println!("{}",block_1_2_content);

    return Ok(());
}
fn main()  {
    // println!("hi");
    // let psi =PSI{};
    // let mut  ctx=Ctx{};
    // psi.execute(mut &ctx);
    // let filepath = String::from("a.txt");// 运行的路径是在根目录哦！
    let mut hashmap: HashMap<String, u32> = HashMap::new();

    // let mut hashmap = HashMap<String,u32>::new();
    // let block1_1_path = String::from("testdata/d1_block1.txt");
    // let block1_2_path = String::from("testdata/d1_block2.txt");
    let block1_1_path = "testdata/d1_block1.txt";
    let block1_2_path = "testdata/d2_block2.txt";
    let a = test(&mut hashmap,block1_1_path);
    let b = test(&mut hashmap,block1_2_path);
    let mut size = 0;
    // let mut thres = 1;
    // in  block loop : the data might be stored in multiple blocks
    for (_, v) in hashmap.iter()
    {
        if * v as usize >= 2{
            size += 1;
        }
    }
    println!("size:{}",size);
    let mut rep:report = report{
        res: Vec::new(),
    };
    let mut r1 = t{
        id: 3,
    };
    rep.res.push(r1);
    let mut r2 = t{
        id: 2,
    };
    rep.res.push(r2);
    println!("rep.res.len(){}",rep.res.len());
    let mut count = 0;
    for i in 1..rep.res.len(){
        println!("{}\n",count );
        count += 1;
    }
}



