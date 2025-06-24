package api

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"v2ray-stat/config"

	statsSingbox "github.com/v2ray/v2ray-core/app/stats/command"
	statsXray "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func GetApiResponse(cfg *config.Config) (*ApiResponse, error) {
	clientConn, err := grpc.NewClient("127.0.0.1:9953", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("error connecting to gRPC server: %w", err)
	}
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var stats []Stat

	switch cfg.CoreType {
	case "xray":
		client := statsXray.NewStatsServiceClient(clientConn)
		req := &statsXray.QueryStatsRequest{
			Pattern: "",
		}
		xrayResp, err := client.QueryStats(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("error executing gRPC request for Xray: %w", err)
		}

		for _, s := range xrayResp.GetStat() {
			stats = append(stats, Stat{
				Name:  s.GetName(),
				Value: strconv.FormatInt(s.GetValue(), 10),
			})
		}

	case "singbox":
		client := statsSingbox.NewStatsServiceClient(clientConn)
		req := &statsSingbox.QueryStatsRequest{
			Pattern: "",
		}
		singboxResp, err := client.QueryStats(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("error executing gRPC request for Singbox: %w", err)
		}
		for _, s := range singboxResp.GetStat() {
			stats = append(stats, Stat{
				Name:  s.GetName(),
				Value: strconv.FormatInt(s.GetValue(), 10),
			})
		}
	}

	return &ApiResponse{Stat: stats}, nil
}
