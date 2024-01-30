use crate::worker_remote::{Context};
use serde::{Deserialize,Serialize};

#[derive(Debug,PartialEq,Serialize,Deserialize)]
pub struct Column{
    pub name:String,
    #[serde(skip_deserializing,skip_serializing)]
    pub idx:u32,
}

#[derive(Debug,PartialEq,Serialize,Deserialize)]
pub struct Argument{
    #[serde(skip_deserializing,skip_serializing)]
    pub pos:i8,
    pub tag:i32,
    pub columns: Vec<Column>,
}

// impl Argument{
//     pub fn from_tee_config(ctx: &mut dyn Context) ->
// }