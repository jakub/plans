// Package protocol defines the JSON contract shared by plansd and the plans CLI.
package protocol

import "time"

// ArtifactResponse is returned after a successful upload.
type ArtifactResponse struct {
	Key         string     `json:"key"`
	URL         string     `json:"url"`
	ContentType string     `json:"content_type"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Size        int64      `json:"size"`
	SHA256      string     `json:"sha256"`
	// Attachments echoes the capability keys a plan bundled, so an uploader
	// learns from the response alone which media deleting this plan deletes.
	// Absent on anything that bundles nothing.
	Attachments []string `json:"attachments,omitempty"`
}

// DeleteResponse reports what a deletion removed. A plan lists itself first and
// then the attachments it bundled. When the deletion removed something but did
// not finish, the response comes back with a 5xx status, Error says why, and
// Failed names the bundled keys that are still present, which the caller may
// delete directly. Error makes this body a superset of ErrorResponse.
type DeleteResponse struct {
	Deleted []string `json:"deleted"`
	Failed  []string `json:"failed,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// ErrorResponse is the stable API error envelope.
type ErrorResponse struct {
	Error string `json:"error"`
}
