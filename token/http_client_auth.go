package token

import (
	"context"
	"errors"

	"github.com/influxdata/influxdb/v2"
	ihttp "github.com/influxdata/influxdb/v2/http"
	"github.com/influxdata/influxdb/v2/pkg/httpc"
)

const prefixAuthorization = "/api/v2/authorizations"

var _ influxdb.AuthorizationService = (*AuthorizationService)(nil)

// AuthorizationService connects to Influx via HTTP using tokens to manage authorizations
type AuthorizationService struct {
	Client *httpc.Client
}

// CreateAuthorization creates a new authorization and sets b.ID with the new identifier.
func (s *AuthorizationService) CreateAuthorization(ctx context.Context, a *influxdb.Authorization) error {
	newAuth, err := newPostAuthorizationRequest(a)
	if err != nil {
		return err
	}

	return s.Client.
		PostJSON(newAuth, prefixAuthorization).
		DecodeJSON(a).
		Do(ctx)
}

// FindAuthorizations returns a list of authorizations that match filter and the total count of matching authorizations.
// Additional options provide pagination & sorting.
func (s *AuthorizationService) FindAuthorizations(ctx context.Context, filter influxdb.AuthorizationFilter, opt ...influxdb.FindOptions) ([]*influxdb.Authorization, int, error) {
	params := ihttp.FindOptionParams(opt...)
	if filter.ID != nil {
		params = append(params, [2]string{"id", filter.ID.String()})
	}
	if filter.UserID != nil {
		params = append(params, [2]string{"userID", filter.UserID.String()})
	}
	if filter.User != nil {
		params = append(params, [2]string{"user", *filter.User})
	}
	if filter.OrgID != nil {
		params = append(params, [2]string{"orgID", filter.OrgID.String()})
	}
	if filter.Org != nil {
		params = append(params, [2]string{"org", *filter.Org})
	}

	var as authsResponse
	err := s.Client.
		Get(prefixAuthorization).
		QueryParams(params...).
		DecodeJSON(&as).
		Do(ctx)
	if err != nil {
		return nil, 0, err
	}

	auths := make([]*influxdb.Authorization, 0, len(as.Auths))
	for _, a := range as.Auths {
		auths = append(auths, a.toinfluxdb())
	}

	return auths, len(auths), nil
}

// FindAuthorizationByToken is not supported by the HTTP authorization service.
func (s *AuthorizationService) FindAuthorizationByToken(ctx context.Context, token string) (*platform.Authorization, error) {
	return nil, errors.New("not supported in HTTP authorization service")
}

// FindAuthorizationByID finds a single Authorization by its ID against a remote influx server.
func (s *AuthorizationService) FindAuthorizationByID(ctx context.Context, id influxdb.ID) (*influxdb.Authorization, error) {
	var b influxdb.Authorization
	err := s.Client.
		Get(prefixAuthorization, id.String()).
		DecodeJSON(&b).
		Do(ctx)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// TODO (al): update authorizations (status and description only)

// DeleteAuthorization removes a authorization by id.
func (s *AuthorizationService) DeleteAuthorization(ctx context.Context, id platform.ID) error {
	return s.Client.
		Delete(prefixAuthorization, id.String()).
		Do(ctx)
}
