package main

import (
	pb "go-grpc/middleware/proto"
	"google.golang.org/grpc"
	"log"
	"net"
)

var addr = "0.0.0.0:50051"

type Server struct {
	pb.HandshakeServiceServer
	pb.EncryptionServiceServer
}

func main() {
	lis, err := net.Listen("tcp", addr)

	if err != nil {
		log.Fatalf("Error in opening connection: %v", err)
	}
	log.Println("Listening to port: ", addr)

	s := grpc.NewServer()
	pb.RegisterHandshakeServiceServer(s, &Server{})
	pb.RegisterEncryptionServiceServer(s, &Server{})

	if err = s.Serve(lis); err != nil {
		log.Fatalf("Fail to serve: %v\n", err)
	}
}
