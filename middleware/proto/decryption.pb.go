// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v4.25.0
// source: decryption.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type DecryptionRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Payload string `protobuf:"bytes,1,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (x *DecryptionRequest) Reset() {
	*x = DecryptionRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_decryption_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DecryptionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DecryptionRequest) ProtoMessage() {}

func (x *DecryptionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_decryption_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DecryptionRequest.ProtoReflect.Descriptor instead.
func (*DecryptionRequest) Descriptor() ([]byte, []int) {
	return file_decryption_proto_rawDescGZIP(), []int{0}
}

func (x *DecryptionRequest) GetPayload() string {
	if x != nil {
		return x.Payload
	}
	return ""
}

type DecryptionResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result string `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *DecryptionResponse) Reset() {
	*x = DecryptionResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_decryption_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DecryptionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DecryptionResponse) ProtoMessage() {}

func (x *DecryptionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_decryption_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DecryptionResponse.ProtoReflect.Descriptor instead.
func (*DecryptionResponse) Descriptor() ([]byte, []int) {
	return file_decryption_proto_rawDescGZIP(), []int{1}
}

func (x *DecryptionResponse) GetResult() string {
	if x != nil {
		return x.Result
	}
	return ""
}

var File_decryption_proto protoreflect.FileDescriptor

var file_decryption_proto_rawDesc = []byte{
	0x0a, 0x10, 0x64, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x0a, 0x6d, 0x69, 0x64, 0x64, 0x6c, 0x65, 0x77, 0x61, 0x72, 0x65, 0x22, 0x2d,
	0x0a, 0x11, 0x44, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0x2c, 0x0a,
	0x12, 0x44, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x32, 0x60, 0x0a, 0x11, 0x44,
	0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x12, 0x4b, 0x0a, 0x0a, 0x44, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1d,
	0x2e, 0x6d, 0x69, 0x64, 0x64, 0x6c, 0x65, 0x77, 0x61, 0x72, 0x65, 0x2e, 0x44, 0x65, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e,
	0x6d, 0x69, 0x64, 0x64, 0x6c, 0x65, 0x77, 0x61, 0x72, 0x65, 0x2e, 0x44, 0x65, 0x63, 0x72, 0x79,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x1a, 0x5a,
	0x18, 0x67, 0x6f, 0x2d, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x6d, 0x69, 0x64, 0x64, 0x6c, 0x65, 0x77,
	0x61, 0x72, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_decryption_proto_rawDescOnce sync.Once
	file_decryption_proto_rawDescData = file_decryption_proto_rawDesc
)

func file_decryption_proto_rawDescGZIP() []byte {
	file_decryption_proto_rawDescOnce.Do(func() {
		file_decryption_proto_rawDescData = protoimpl.X.CompressGZIP(file_decryption_proto_rawDescData)
	})
	return file_decryption_proto_rawDescData
}

var file_decryption_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_decryption_proto_goTypes = []interface{}{
	(*DecryptionRequest)(nil),  // 0: middleware.DecryptionRequest
	(*DecryptionResponse)(nil), // 1: middleware.DecryptionResponse
}
var file_decryption_proto_depIdxs = []int32{
	0, // 0: middleware.DecryptionService.Decryption:input_type -> middleware.DecryptionRequest
	1, // 1: middleware.DecryptionService.Decryption:output_type -> middleware.DecryptionResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_decryption_proto_init() }
func file_decryption_proto_init() {
	if File_decryption_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_decryption_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DecryptionRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_decryption_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DecryptionResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_decryption_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_decryption_proto_goTypes,
		DependencyIndexes: file_decryption_proto_depIdxs,
		MessageInfos:      file_decryption_proto_msgTypes,
	}.Build()
	File_decryption_proto = out.File
	file_decryption_proto_rawDesc = nil
	file_decryption_proto_goTypes = nil
	file_decryption_proto_depIdxs = nil
}
