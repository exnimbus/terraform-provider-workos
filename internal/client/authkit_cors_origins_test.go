// Copyright (c) OSO DevOps
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const corsOriginFixture = `{
  "id": "cors_origin_01JYQ5B9Q6ZP8K4R2T1V0X9ABC",
  "object": "cors_origin",
  "origin": "https://app.example.com",
  "created_at": "2026-01-15T12:00:00.000Z",
  "updated_at": "2026-01-15T12:00:00.000Z"
}`

func TestCORSOriginsClientCreateAndDelete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if r.URL.Path != "/user_management/cors_origins" {
				t.Fatalf("expected /user_management/cors_origins, got %s", r.URL.Path)
			}
			var body CORSOriginCreateRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode request body: %v", err)
			}
			if body.Origin != "https://app.example.com" {
				t.Fatalf("unexpected request body: %#v", body)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(corsOriginFixture))
		case http.MethodDelete:
			if r.URL.Path != "/user_management/cors_origins/cors_origin_01JYQ5B9Q6ZP8K4R2T1V0X9ABC" {
				t.Fatalf("unexpected delete path: %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	}))
	defer server.Close()

	client, err := NewClient("sk_test", "", server.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	origin, err := client.CreateCORSOrigin(context.Background(), &CORSOriginCreateRequest{
		Origin: "https://app.example.com",
	})
	if err != nil {
		t.Fatalf("CreateCORSOrigin returned error: %v", err)
	}
	if origin.ID != "cors_origin_01JYQ5B9Q6ZP8K4R2T1V0X9ABC" || origin.Origin != "https://app.example.com" {
		t.Fatalf("unexpected CORS origin response: %#v", origin)
	}

	if err := client.DeleteCORSOrigin(context.Background(), origin.ID); err != nil {
		t.Fatalf("DeleteCORSOrigin returned error: %v", err)
	}
}

func TestCORSOriginsClientListPaginationAndGet(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/user_management/cors_origins" {
			t.Fatalf("expected /user_management/cors_origins, got %s", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "100" {
			t.Fatalf("expected limit=100, got %s", r.URL.Query().Get("limit"))
		}

		w.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			if r.URL.Query().Get("after") != "" {
				t.Fatalf("did not expect after on first page, got %s", r.URL.Query().Get("after"))
			}
			_, _ = w.Write([]byte(`{"data": [], "list_metadata": {"after": "cursor_1"}}`))
			return
		}
		if r.URL.Query().Get("after") != "cursor_1" {
			t.Fatalf("expected after=cursor_1, got %s", r.URL.Query().Get("after"))
		}
		_, _ = w.Write([]byte(`{"data": [` + corsOriginFixture + `], "list_metadata": {}}`))
	}))
	defer server.Close()

	client, err := NewClient("sk_test", "", server.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	origin, err := client.GetCORSOrigin(context.Background(), "cors_origin_01JYQ5B9Q6ZP8K4R2T1V0X9ABC")
	if err != nil {
		t.Fatalf("GetCORSOrigin returned error: %v", err)
	}
	if origin.Origin != "https://app.example.com" {
		t.Fatalf("unexpected CORS origin: %#v", origin)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
}
