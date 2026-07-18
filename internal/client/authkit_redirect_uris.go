// Copyright (c) OSO DevOps
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// RedirectURI represents an AuthKit redirect URI.
type RedirectURI struct {
	ID        string    `json:"id"`
	Object    string    `json:"object"`
	URI       string    `json:"uri"`
	Default   bool      `json:"default"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RedirectURICreateRequest represents the request to create an AuthKit redirect URI.
type RedirectURICreateRequest struct {
	URI string `json:"uri"`
}

// RedirectURIListResponse represents the response from listing AuthKit redirect URIs.
type RedirectURIListResponse struct {
	Data         []RedirectURI `json:"data"`
	ListMetadata ListMetadata  `json:"list_metadata"`
}

// CreateRedirectURI creates an AuthKit redirect URI.
func (c *Client) CreateRedirectURI(ctx context.Context, req *RedirectURICreateRequest) (*RedirectURI, error) {
	var redirectURI RedirectURI
	err := c.Post(ctx, "/user_management/redirect_uris", req, &redirectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to create redirect URI: %w", err)
	}
	return &redirectURI, nil
}

// ListRedirectURIs lists AuthKit redirect URIs.
func (c *Client) ListRedirectURIs(ctx context.Context) (*RedirectURIListResponse, error) {
	var all RedirectURIListResponse
	params := url.Values{}
	applyDefaultPagination(params)

	for {
		var page RedirectURIListResponse
		err := c.Get(ctx, pathWithQuery("/user_management/redirect_uris", params), &page)
		if err != nil {
			return nil, fmt.Errorf("failed to list redirect URIs: %w", err)
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

// GetRedirectURI finds an AuthKit redirect URI by ID using the list endpoint.
func (c *Client) GetRedirectURI(ctx context.Context, id string) (*RedirectURI, error) {
	resp, err := c.ListRedirectURIs(ctx)
	if err != nil {
		return nil, err
	}

	for _, redirectURI := range resp.Data {
		if redirectURI.ID == id {
			return &redirectURI, nil
		}
	}

	return nil, &APIError{
		StatusCode: 404,
		Message:    fmt.Sprintf("no redirect URI found with ID: %s", id),
	}
}

// DeleteRedirectURI deletes an AuthKit redirect URI.
func (c *Client) DeleteRedirectURI(ctx context.Context, id string) error {
	err := c.Delete(ctx, "/user_management/redirect_uris/"+url.PathEscape(id))
	if err != nil {
		return fmt.Errorf("failed to delete redirect URI: %w", err)
	}
	return nil
}
