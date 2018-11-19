extern crate wallet;
extern crate bitcoin_core_io;
extern crate bitcoin;
extern crate grpc;
extern crate protobuf;
extern crate tls_api;
extern crate tls_api_native_tls;
extern crate crossbeam;
extern crate bitcoin_rpc_client;
#[macro_use]
extern crate log;

pub mod server;
pub mod client;
pub mod walletrpc;
mod walletrpc_grpc;