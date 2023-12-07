package main

import (
	"context"
	pb "go-grpc/middleware/proto"
)

func (s *Server) Decryption(context.Context, *pb.DecryptionRequest) (*pb.DecryptionResponse, error) {

	return &pb.DecryptionResponse{Result: "some val"}, nil
}
