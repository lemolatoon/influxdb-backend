package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
)

const (
	MinMinutes      = 1
	MaxMinutes      = 1440
	QueryTimeout    = 10 * time.Second
	ServerReadTO    = 5 * time.Second
	ServerWriteTO   = 10 * time.Second
	ServerIdleTO    = 120 * time.Second
	RateLimitPerMin = 60 * 100
	RateLimitPerSec = 1 * 100
)

type DataPoint struct {
	Time        time.Time `json:"time"`
	Temperature *float64  `json:"temperature,omitempty"`
	Humidity    *float64  `json:"humidity,omitempty"`
}

type RateLimiter struct {
	mu   sync.Mutex
	byIP map[string][]time.Time
}

func (r *RateLimiter) Allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	fromMin := now.Add(-1 * time.Minute)
	fromSec := now.Add(-1 * time.Second)

	times := r.byIP[ip]
	var filtered []time.Time
	for _, t := range times {
		if t.After(fromMin) {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) >= RateLimitPerMin {
		return false
	}
	var secCount int
	for _, t := range filtered {
		if t.After(fromSec) {
			secCount++
		}
	}
	if secCount >= RateLimitPerSec {
		return false
	}
	r.byIP[ip] = append(filtered, now)
	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
		next.ServeHTTP(w, r)
	})
}

func main() {
	// 必須 env チェック
	influxURL := os.Getenv("INFLUXDB_URL")
	influxToken := os.Getenv("INFLUXDB_TOKEN")
	influxOrg := os.Getenv("INFLUXDB_ORG")
	bucket := os.Getenv("INFLUXDB_BUCKET")
	if influxURL == "" || influxToken == "" || influxOrg == "" || bucket == "" {
		log.Fatal("Missing INFLUXDB_URL/TOKEN/ORG/BUCKET")
	}

	client := influxdb2.NewClient(influxURL, influxToken) // Go client 初期化 :contentReference[oaicite:3]{index=3}
	queryAPI := client.QueryAPI(influxOrg)

	rl := &RateLimiter{byIP: make(map[string][]time.Time)}
	mux := http.NewServeMux()

	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !rl.Allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		minsStr := r.URL.Query().Get("minutes")
		mins, err := strconv.Atoi(minsStr)
		if err != nil || mins < MinMinutes || mins > MaxMinutes {
			http.Error(w, "invalid minutes (1–1440)", http.StatusBadRequest)
			return
		}

		dur := time.Duration(mins) * time.Minute
		secs := int(math.Ceil(dur.Seconds() / 500.0))
		if secs < 1 {
			secs = 1
		}
		window := fmt.Sprintf("%ds", secs)

		// 安全な文字列結合による Flux クエリ
		flux := fmt.Sprintf(`
            from(bucket: "%s")
              |> range(start: -%dm, stop: now())
              |> filter(fn: (r) => r._measurement == "sensor_data" and r.sensor == "AHT21B")
              |> filter(fn: (r) => r._field == "temperature" or r._field == "humidity")
              |> aggregateWindow(every: %s, fn: mean, createEmpty: false)
              |> pivot(rowKey:["_time"], columnKey:["_field"], valueColumn:"_value")
        `, bucket, mins, window)

		ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
		defer cancel()

		result, err := queryAPI.Query(ctx, flux) // 型安全 API 呼び出しに戻す :contentReference[oaicite:4]{index=4}
		if err != nil {
			log.Printf("query error: %v", err)
			http.Error(w, "query error", http.StatusInternalServerError)
			return
		}
		defer result.Close()

		var points []DataPoint
		for result.Next() {
			rec := result.Record()
			dp := DataPoint{Time: rec.Time()}
			if v, ok := rec.ValueByKey("temperature").(float64); ok {
				dp.Temperature = &v
			}
			if v, ok := rec.ValueByKey("humidity").(float64); ok {
				dp.Humidity = &v
			}
			points = append(points, dp)
		}
		if err := result.Err(); err != nil {
			log.Printf("cursor error: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(points)
	})

	server := &http.Server{
		Addr:         ":8080",
		Handler:      securityHeaders(mux),
		ReadTimeout:  ServerReadTO,
		WriteTimeout: ServerWriteTO,
		IdleTimeout:  ServerIdleTO,
	}

	log.Println("Server listening on :8080")
	log.Fatal(server.ListenAndServe()) // TLS は Cloudflare Tunnel で終端
}
