package token

import (
	"context"

	"github.com/influxdata/influxdb/v2"
	"github.com/influxdata/influxdb/v2/kv"
)

func (s *Service) FindAuthorizationByID(ctx context.Context, id influxdb.ID) (*influxdb.Authorization, error) {
	var a *influxdb.Authorization
	err := s.Store.View(ctx, func(tx kv.Tx) error {
		auth, err := s.Store.GetAuthorizationByID(ctx, tx, id)
		if err != nil {
			return nil
		}

		a = auth
		return nil
	})

	if err != nil {
		return nil, err
	}

	return a, nil
}

// FindAuthorizationByToken returns a authorization by token for a particular authorization.
func (s *Service) FindAuthorizationByToken(ctx context.Context, n string) (*influxdb.Authorization, error) {
	var a *influxdb.Authorization
	err := s.kv.View(ctx, func(tx Tx) error {
		auth, err := s.GetAuthorizationByToken(ctx, tx, n)
		if err != nil {
			return err
		}

		a = auth

		return nil
	})

	if err != nil {
		return nil, err
	}

	return a, nil
}

// FindAuthorizations retrives all authorizations that match an arbitrary authorization filter.
// Filters using ID, or Token should be efficient.
// Other filters will do a linear scan across all authorizations searching for a match.
func (s *Service) FindAuthorizations(ctx context.Context, filter influxdb.AuthorizationFilter, opt ...influxdb.FindOptions) ([]*influxdb.Authorization, int, error) {
	if filter.ID != nil {
		a, err := s.GetAuthorizationByID(ctx, *filter.ID)
		if err != nil {
			return nil, 0, &influxdb.Error{
				Err: err,
			}
		}

		return []*influxdb.Authorization{a}, 1, nil
	}

	if filter.Token != nil {
		a, err := s.GetAuthorizationByToken(ctx, *filter.Token)
		if err != nil {
			return nil, 0, &influxdb.Error{
				Err: err,
			}
		}

		return []*influxdb.Authorization{a}, 1, nil
	}

	as := []*influxdb.Authorization{}
	err := s.kv.View(ctx, func(tx Tx) error {
		auths, err := s.ListAuthorizations(ctx, tx, filter)
		if err != nil {
			return err
		}
		as = auths
		return nil
	})

	if err != nil {
		return nil, 0, &influxdb.Error{
			Err: err,
		}
	}

	return as, len(as), nil
}

// UpdateAuthorization updates the status and description if available.
func (s *Service) UpdateAuthorization(ctx context.Context, id influxdb.ID, upd *influxdb.AuthorizationUpdate) (*influxdb.Authorization, error) {
	auth, err := s.findAuthorizationByID(ctx, tx, id)
	if err != nil {
		return nil, err
	}

	if upd.Status != nil {
		a.Status = *upd.Status
	}
	if upd.Description != nil {
		a.Description = *upd.Description
	}

	now := s.TimeGenerator.Now()
	a.SetUpdatedAt(now)

	var a *influxdb.Authorization
	var err error
	err = s.kv.Update(ctx, func(tx Tx) error {
		a, err = s.UpdateAuthorization(ctx, tx, id, upd)
		return err
	})
	return a, err
}

func (s *Service) DeleteAuthorization(ctx context.Context, id influxdb.ID) error {
	return s.kv.Update(ctx, func(tx Tx) (err error) {
		return s.deleteAuthorization(ctx, tx, id)
	})
}
