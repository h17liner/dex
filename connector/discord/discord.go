package discord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"golang.org/x/oauth2"
	"io"
	"net/http"
)

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

type Config struct {
	ClientID     string   `json:"clientID"`
	ClientSecret string   `json:"clientSecret"`
	RedirectURI  string   `json:"redirectURI"`
	Scopes       []string `json:"scopes"`
	Org          Org      `json:"org"`
}

type Org struct {
	Name  string   `json:"name"`
	Teams []string `json:"teams"`
}

func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {

	d := &discordConnector{
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		redirectURI:  c.RedirectURI,
		apiURL:       "https://discord.com/api",
		logger:       logger,
		org:          c.Org,
	}

	return d, nil
}

type discordConnector struct {
	clientID     string
	clientSecret string
	redirectURI  string

	logger     log.Logger
	apiURL     string
	httpClient *http.Client

	org Org

	verifier *oidc.IDTokenVerifier
}

func (c *discordConnector) oauth2Config(scopes connector.Scopes) *oauth2.Config {
	// 'read:org' scope is required by the GitHub API, and thus for dex to ensure
	// a user is a member of orgs and teams provided in configs.
	discordScopes := []string{"email"}
	if scopes.Groups {
		discordScopes = append(discordScopes, "guilds.members.read", "guilds")
	}

	endpoint := oauth2.Endpoint{
		AuthURL:  "https://discord.com/api/oauth2/authorize",
		TokenURL: "https://discord.com/api/oauth2/token",
	}

	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     endpoint,
		Scopes:       discordScopes,
		RedirectURL:  c.redirectURI,
	}
}

func (c *discordConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	return c.oauth2Config(scopes).AuthCodeURL(state), nil
}

func (c *discordConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	c.logger.Infof("Handling callback")
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	oauth2Config := c.oauth2Config(s)
	ctx := r.Context()

	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("discord: failed to get token: %v", err)
	}

	c.logger.Infof("Got token %#v", token)

	client := oauth2Config.Client(ctx, token)
	user, err := c.user(ctx, client)
	if err != nil {
		return identity, fmt.Errorf("discord: get user: %v", err)
	}

	identity = connector.Identity{
		UserID:            user.ID,
		Username:          user.Username,
		PreferredUsername: user.Username + "#" + user.Discriminator,
		Email:             user.Email,
		EmailVerified:     true,
	}

	groupIds, err := c.getGroup(ctx, client, user.Username)
	if err != nil {
		return identity, err
	}
	identity.Groups = groupIds

	return identity, nil
}

type connectorData struct {
	// GitHub's OAuth2 tokens never expire. We don't need a refresh token.
	AccessToken string `json:"accessToken"`
}

func (c *discordConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	c.logger.Infof("!!Refresh: enter: %+v", s)

	if len(identity.ConnectorData) == 0 {
		return identity, errors.New("no upstream access token found")
	}

	var data connectorData
	if err := json.Unmarshal(identity.ConnectorData, &data); err != nil {
		return identity, fmt.Errorf("github: unmarshal access token: %v", err)
	}

	client := c.oauth2Config(s).Client(ctx, &oauth2.Token{AccessToken: data.AccessToken})
	user, err := c.user(ctx, client)
	if err != nil {
		return identity, fmt.Errorf("github: get user: %v", err)
	}

	identity.Username = user.Username
	identity.PreferredUsername = user.Username + "#" + user.Discriminator
	identity.Email = user.Email

	groupIds, err := c.getGroup(ctx, client, user.Username)
	if err != nil {
		return identity, err
	}
	identity.Groups = groupIds

	return identity, nil
}

type user struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Email         string `json:"email"`
}

type group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type member struct {
	RolesIds []string `json:"roles"`
}

func (c *discordConnector) getGroup(ctx context.Context, client *http.Client, userLogin string) ([]string, error) {
	groupId, err := c.groupId(ctx, client)
	if err != nil {
		return []string{}, err
	}

	if groupId == "" {
		return []string{}, fmt.Errorf("no guild found or user '%q' not a member of required guild", userLogin)
	}

	getRoleIds, err := c.getRoleIds(ctx, client, groupId)
	if err != nil {
		return getRoleIds, err
	}

	if c.org.Teams == nil {
		return getRoleIds, nil
	}

	diffTeamIds := []string{}

	for _, roleId := range getRoleIds {
		for _, teamId := range c.org.Teams {
			if roleId == teamId {
				diffTeamIds = append(diffTeamIds, teamId)
			}
		}
	}

	if len(diffTeamIds) > 0 {
		return diffTeamIds, nil
	}

	return []string{}, fmt.Errorf("user '%q' not a member of required role", userLogin)
}

func (c *discordConnector) groupId(ctx context.Context, client *http.Client) (string, error) {
	groupName := c.org.Name
	url := fmt.Sprintf("%s/users/@me/guilds", c.apiURL)
	var groups []group
	if err := makeGetRequest(ctx, client, url, &groups); err != nil {
		return "", err
	}

	for _, group := range groups {
		if group.Name == groupName {
			return group.ID, nil
		}
	}

	return "", fmt.Errorf("discord: group: %s didnt find or membor doesnt a part of group", groupName)
}

func (c *discordConnector) getRoleIds(ctx context.Context, client *http.Client, groupId string) ([]string, error) {
	url := fmt.Sprintf("%s/users/@me/guilds/%s/member", c.apiURL, groupId)
	var member member
	if err := makeGetRequest(ctx, client, url, &member); err != nil {
		return nil, err
	}

	return member.RolesIds, nil
}

func (c *discordConnector) user(ctx context.Context, client *http.Client) (user, error) {
	url := fmt.Sprintf("%s/users/@me", c.apiURL)
	var u user
	if err := makeGetRequest(ctx, client, url, &u); err != nil {
		return u, err
	}

	return u, nil
}

func makeGetRequest(ctx context.Context, client *http.Client, apiURL string, v interface{}) error {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("discord: new req: %v", err)
	}

	req = req.WithContext(ctx)
	resp, err := client.Do(req)

	if err != nil {
		return fmt.Errorf("discord: get URL %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("discord: read body: %v", err)
		}

		return fmt.Errorf("%s: %s", resp.Status, body)
	}

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("discord: failed to decode response: %v", err)
	}

	return nil
}
