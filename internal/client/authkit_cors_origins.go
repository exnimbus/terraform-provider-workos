// Copyright (c) OSO DevOps
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// CORSOrigin represents an AuthKit CORS origin.
type CORSOrigin struct {
	ID        string    `json:"id"`
	Object    string    `json:"object"`
	Origin    string    `json:"origin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CORSOriginCreateRequest represents the request to create an AuthKit CORS origin.
type CORSOriginCreateRequest struct {
	Origin string `json:"origin"`
}

// CORSOriginListResponse represents the response from listing AuthKit CORS origins.
type CORSOriginListResponse struct {
	Data         []CORSOrigin `json:"data"`
	ListMetadata ListMetadata `json:"list_metadata"`
}

// CreateCORSOrigin creates an AuthKit CORS origin.
func (c *Client) CreateCORSOrigin(ctx context.Context, req *CORSOriginCreateRequest) (*CORSOrigin, error) {
	var origin CORSOrigin
	err := c.Post(ctx, "/user_management/cors_origins", req, &origin)
	if err != nil {
		return nil, fmt.Errorf("failed to create CORS origin: %w", err)
	}
	return &origin, nil
}

// ListCORSOrigins lists AuthKit CORS origins.
func (c *Client) ListCORSOrigins(ctx context.Context) (*CORSOriginListResponse, error) {
	var all CORSOriginListResponse
	params := url.Values{}
	applyDefaultPagination(params)

	for {
		var page CORSOriginListResponse
		err := c.Get(ctx, pathWithQuery("/user_management/cors_origins", params), &page)
		if err != nil {
			return nil, fmt.Errorf("failed to list CORS origins: %w", err)
		}

		all.Data = append(all.Data, page.Data...)
		all.ListMetadata = page.ListMetadata
		if page.ListMetadata.After == "" {
			break
		}
		params.Set("after", page.ListMetadata.After)
	}

	return &all, nil
}

// GetCORSOrigin finds an AuthKit CORS origin by ID using the list endpoint.
func (c *Client) GetCORSOrigin(ctx context.Context, id string) (*CORSOrigin, error) {
	resp, err := c.ListCORSOrigins(ctx)
	if err != nil {
		return nil, err
	}

	for _, origin := range resp.Data {
		if origin.ID == id {
			return &origin, nil
		}
	}

	return nil, &APIError{
		StatusCode: 404,
		Message:    fmt.Sprintf("no CORS origin found with ID: %s", id),
	}
}

// DeleteCORSOrigin deletes an AuthKit CORS origin.
func (c *Client) DeleteCORSOrigin(ctx context.Context, id string) error {
	err := c.Delete(ctx, "/user_management/cors_origins/"+url.PathEscape(id))
	if err != nil {
		return fmt.Errorf("failed to delete CORS origin: %w", err)
	}
	return nil
}
