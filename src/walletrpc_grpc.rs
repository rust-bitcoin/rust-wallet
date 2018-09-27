// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]


// interface

pub trait Wallet {
    fn new_address(&self, o: ::grpc::RequestOptions, p: super::walletrpc::NewAddressRequest) -> ::grpc::SingleResponse<super::walletrpc::NewAddressResponse>;

    fn get_utxo_list(&self, o: ::grpc::RequestOptions, p: super::walletrpc::GetUtxoListRequest) -> ::grpc::SingleResponse<super::walletrpc::GetUtxoListResponse>;

    fn sync_with_tip(&self, o: ::grpc::RequestOptions, p: super::walletrpc::SyncWithTipRequest) -> ::grpc::SingleResponse<super::walletrpc::SyncWithTipResponse>;

    fn make_tx(&self, o: ::grpc::RequestOptions, p: super::walletrpc::MakeTxRequest) -> ::grpc::SingleResponse<super::walletrpc::MakeTxResponse>;
}

// client

pub struct WalletClient {
    grpc_client: ::grpc::Client,
    method_NewAddress: ::std::sync::Arc<::grpc::rt::MethodDescriptor<super::walletrpc::NewAddressRequest, super::walletrpc::NewAddressResponse>>,
    method_GetUtxoList: ::std::sync::Arc<::grpc::rt::MethodDescriptor<super::walletrpc::GetUtxoListRequest, super::walletrpc::GetUtxoListResponse>>,
    method_SyncWithTip: ::std::sync::Arc<::grpc::rt::MethodDescriptor<super::walletrpc::SyncWithTipRequest, super::walletrpc::SyncWithTipResponse>>,
    method_MakeTx: ::std::sync::Arc<::grpc::rt::MethodDescriptor<super::walletrpc::MakeTxRequest, super::walletrpc::MakeTxResponse>>,
}

impl WalletClient {
    pub fn with_client(grpc_client: ::grpc::Client) -> Self {
        WalletClient {
            grpc_client: grpc_client,
            method_NewAddress: ::std::sync::Arc::new(::grpc::rt::MethodDescriptor {
                name: "/walletrpc.Wallet/NewAddress".to_string(),
                streaming: ::grpc::rt::GrpcStreaming::Unary,
                req_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                resp_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
            }),
            method_GetUtxoList: ::std::sync::Arc::new(::grpc::rt::MethodDescriptor {
                name: "/walletrpc.Wallet/GetUtxoList".to_string(),
                streaming: ::grpc::rt::GrpcStreaming::Unary,
                req_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                resp_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
            }),
            method_SyncWithTip: ::std::sync::Arc::new(::grpc::rt::MethodDescriptor {
                name: "/walletrpc.Wallet/SyncWithTip".to_string(),
                streaming: ::grpc::rt::GrpcStreaming::Unary,
                req_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                resp_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
            }),
            method_MakeTx: ::std::sync::Arc::new(::grpc::rt::MethodDescriptor {
                name: "/walletrpc.Wallet/MakeTx".to_string(),
                streaming: ::grpc::rt::GrpcStreaming::Unary,
                req_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                resp_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
            }),
        }
    }

    pub fn new_plain(host: &str, port: u16, conf: ::grpc::ClientConf) -> ::grpc::Result<Self> {
        ::grpc::Client::new_plain(host, port, conf).map(|c| {
            WalletClient::with_client(c)
        })
    }
    pub fn new_tls<C : ::tls_api::TlsConnector>(host: &str, port: u16, conf: ::grpc::ClientConf) -> ::grpc::Result<Self> {
        ::grpc::Client::new_tls::<C>(host, port, conf).map(|c| {
            WalletClient::with_client(c)
        })
    }
}

impl Wallet for WalletClient {
    fn new_address(&self, o: ::grpc::RequestOptions, p: super::walletrpc::NewAddressRequest) -> ::grpc::SingleResponse<super::walletrpc::NewAddressResponse> {
        self.grpc_client.call_unary(o, p, self.method_NewAddress.clone())
    }

    fn get_utxo_list(&self, o: ::grpc::RequestOptions, p: super::walletrpc::GetUtxoListRequest) -> ::grpc::SingleResponse<super::walletrpc::GetUtxoListResponse> {
        self.grpc_client.call_unary(o, p, self.method_GetUtxoList.clone())
    }

    fn sync_with_tip(&self, o: ::grpc::RequestOptions, p: super::walletrpc::SyncWithTipRequest) -> ::grpc::SingleResponse<super::walletrpc::SyncWithTipResponse> {
        self.grpc_client.call_unary(o, p, self.method_SyncWithTip.clone())
    }

    fn make_tx(&self, o: ::grpc::RequestOptions, p: super::walletrpc::MakeTxRequest) -> ::grpc::SingleResponse<super::walletrpc::MakeTxResponse> {
        self.grpc_client.call_unary(o, p, self.method_MakeTx.clone())
    }
}

// server

pub struct WalletServer;


impl WalletServer {
    pub fn new_service_def<H : Wallet + 'static + Sync + Send + 'static>(handler: H) -> ::grpc::rt::ServerServiceDefinition {
        let handler_arc = ::std::sync::Arc::new(handler);
        ::grpc::rt::ServerServiceDefinition::new("/walletrpc.Wallet",
            vec![
                ::grpc::rt::ServerMethod::new(
                    ::std::sync::Arc::new(::grpc::rt::MethodDescriptor {
                        name: "/walletrpc.Wallet/NewAddress".to_string(),
                        streaming: ::grpc::rt::GrpcStreaming::Unary,
                        req_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                        resp_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                    }),
                    {
                        let handler_copy = handler_arc.clone();
                        ::grpc::rt::MethodHandlerUnary::new(move |o, p| handler_copy.new_address(o, p))
                    },
                ),
                ::grpc::rt::ServerMethod::new(
                    ::std::sync::Arc::new(::grpc::rt::MethodDescriptor {
                        name: "/walletrpc.Wallet/GetUtxoList".to_string(),
                        streaming: ::grpc::rt::GrpcStreaming::Unary,
                        req_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                        resp_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                    }),
                    {
                        let handler_copy = handler_arc.clone();
                        ::grpc::rt::MethodHandlerUnary::new(move |o, p| handler_copy.get_utxo_list(o, p))
                    },
                ),
                ::grpc::rt::ServerMethod::new(
                    ::std::sync::Arc::new(::grpc::rt::MethodDescriptor {
                        name: "/walletrpc.Wallet/SyncWithTip".to_string(),
                        streaming: ::grpc::rt::GrpcStreaming::Unary,
                        req_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                        resp_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                    }),
                    {
                        let handler_copy = handler_arc.clone();
                        ::grpc::rt::MethodHandlerUnary::new(move |o, p| handler_copy.sync_with_tip(o, p))
                    },
                ),
                ::grpc::rt::ServerMethod::new(
                    ::std::sync::Arc::new(::grpc::rt::MethodDescriptor {
                        name: "/walletrpc.Wallet/MakeTx".to_string(),
                        streaming: ::grpc::rt::GrpcStreaming::Unary,
                        req_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                        resp_marshaller: Box::new(::grpc::protobuf::MarshallerProtobuf),
                    }),
                    {
                        let handler_copy = handler_arc.clone();
                        ::grpc::rt::MethodHandlerUnary::new(move |o, p| handler_copy.make_tx(o, p))
                    },
                ),
            ],
        )
    }
}
