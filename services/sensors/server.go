// Package sensors contains a gRPC based sensors service server
package sensors

import (
	"context"

	commonpb "go.viam.com/api/common/v1"
	pb "go.viam.com/api/service/sensors/v1"

	"go.viam.com/rdk/protoutils"
	"go.viam.com/rdk/resource"
)

// serviceServer implements the SensorsService from sensors.proto.
type serviceServer struct {
	pb.UnimplementedSensorsServiceServer
	coll resource.APIResourceCollection[Service]
}

// NewRPCServiceServer constructs a sensors gRPC service server.
// It is intentionally untyped to prevent use outside of tests.
func NewRPCServiceServer(coll resource.APIResourceCollection[Service]) interface{} {
	return &serviceServer{coll: coll}
}

//nolint:staticcheck
func (server *serviceServer) GetSensors(
	ctx context.Context,
	req *pb.GetSensorsRequest,
) (*pb.GetSensorsResponse, error) {
	//nolint:staticcheck
	svc, err := server.coll.Resource(req.Name)
	if err != nil {
		return nil, err
	}
	//nolint:staticcheck
	names, err := svc.Sensors(ctx, req.Extra.AsMap())
	if err != nil {
		return nil, err
	}
	sensorNames := make([]*commonpb.ResourceName, 0, len(names))
	for _, name := range names {
		sensorNames = append(sensorNames, protoutils.ResourceNameToProto(name))
	}

	//nolint:staticcheck
	return &pb.GetSensorsResponse{SensorNames: sensorNames}, nil
}

//nolint:staticcheck
func (server *serviceServer) GetReadings(
	ctx context.Context,
	req *pb.GetReadingsRequest,
) (*pb.GetReadingsResponse, error) {
	//nolint:staticcheck
	svc, err := server.coll.Resource(req.Name)
	if err != nil {
		return nil, err
	}
	//nolint:staticcheck
	sensorNames := make([]resource.Name, 0, len(req.SensorNames))
	//nolint:staticcheck
	for _, name := range req.SensorNames {
		sensorNames = append(sensorNames, protoutils.ResourceNameFromProto(name))
	}

	//nolint:staticcheck
	readings, err := svc.Readings(ctx, sensorNames, req.Extra.AsMap())
	if err != nil {
		return nil, err
	}

	//nolint:staticcheck
	readingsP := make([]*pb.Readings, 0, len(readings))
	for _, reading := range readings {
		rReading, err := protoutils.ReadingGoToProto(reading.Readings)
		if err != nil {
			return nil, err
		}
		//nolint:staticcheck
		readingP := &pb.Readings{
			Name:     protoutils.ResourceNameToProto(reading.Name),
			Readings: rReading,
		}
		readingsP = append(readingsP, readingP)
	}

	//nolint:staticcheck
	return &pb.GetReadingsResponse{Readings: readingsP}, nil
}

// DoCommand receives arbitrary commands.
func (server *serviceServer) DoCommand(ctx context.Context,
	req *commonpb.DoCommandRequest,
) (*commonpb.DoCommandResponse, error) {
	svc, err := server.coll.Resource(req.Name)
	if err != nil {
		return nil, err
	}
	return protoutils.DoFromResourceServer(ctx, svc, req)
}
