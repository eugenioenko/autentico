package client

// ClientByClientIDIncludingDisabled returns the client regardless of is_active status.
// Used by admin endpoints that need to view or modify deactivated clients.
func ClientByClientIDIncludingDisabled(clientID string) (*Client, error) {
	return queryClient("client_id = ?", clientID)
}

// ClientByIDIncludingDisabled returns the client regardless of is_active status.
// Used by admin endpoints that need to view or modify deactivated clients.
func ClientByIDIncludingDisabled(id string) (*Client, error) {
	return queryClient("id = ?", id)
}
