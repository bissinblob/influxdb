package token

import (
	"context"
	"encoding/json"

	influxdb "github.com/influxdata/influxdb/v2"
	"github.com/influxdata/influxdb/v2/kv"
)

func authIndexKey(n string) []byte {
	return []byte(n)
}

func authIndexBucket(tx kv.Tx) (kv.Bucket, error) {
	b, err := tx.Bucket([]byte(authIndex))
	if err != nil {
		return nil, UnexpectedAuthIndexError(err)
	}

	return b, nil
}

func (s *Store) initializeAuths(ctx context.Context, tx kv.Tx) error {
	if _, err := tx.Bucket(authBucket); err != nil {
		return err
	}
	if _, err := authIndexBucket(tx); err != nil {
		return err
	}
	return nil
}

func encodeAuthorization(a *influxdb.Authorization) ([]byte, error) {
	switch a.Status {
	case influxdb.Active, influxdb.Inactive:
	case "":
		a.Status = influxdb.Active
	default:
		return nil, &influxdb.Error{
			Code: influxdb.EInvalid,
			Msg:  "unknown authorization status",
		}
	}

	return json.Marshal(a)
}

func decodeAuthorization(b []byte) (*influxdb.Authorization, error) {
	a := &influxdb.Authorization{}
	if err := json.Unmarshal(b, a); err != nil {
		return nil, &influxdb.Error{
			Code: influxdb.EInvalid,
			Err:  err,
		}
	}
	if a.Status == "" {
		a.Status = influxdb.Active
	}
	return a, nil
}

// CreateAuthorization takes an Authorization object and saves it in storage using its token
// using its token property as an index
func (s *Store) CreateAuthorization(ctx context.Context, tx kv.Tx, a *influxdb.Authorization) error {
	if !a.ID.Valid() {
		id, err := s.generateSafeID(ctx, tx, authBucket)
		if err != nil {
			return nil
		}
		a.ID = id
	}

	v, err := encodeAuthorization(a)
	if err != nil {
		return &influxdb.Error{
			Code: influxdb.EInvalid,
			Err:  err,
		}
	}

	encodedID, err := a.ID.Encode()
	if err != nil {
		return ErrInvalidAuthIDError(err)
	}

	idx, err := authIndexBucket(tx)
	if err != nil {
		return err
	}

	// check that token is unique
	_, err = idx.Get([]byte(a.Token))
	if err == nil {
		return ErrTokenAlreadyExistsError
	} else if !kv.IsNotFound(err) {
		return ErrInternalServiceError(err)
	}

	b, err := tx.Bucket(authBucket)
	if err != nil {
		return err
	}

	if err := idx.Put(authIndexKey(a.Token), encodedID); err != nil {
		return &influxdb.Error{
			Code: influxdb.EInternal,
			Err:  err,
		}
	}

	if err := b.Put(encodedID, v); err != nil {
		return &influxdb.Error{
			Err: err,
		}
	}

	return nil

}

// GetAuthorization gets an authorization by its ID from the auth bucket in kv
func (s *Store) GetAuthorizationByID(ctx context.Context, tx kv.Tx, id influxdb.ID) (a *influxdb.Authorization, err error) {
	encodedID, err := id.Encode()
	if err != nil {
		return nil, ErrInvalidAuthID
	}

	b, err := tx.Bucket(authBucket)
	if err != nil {
		return nil, ErrInternalServiceError(err)
	}

	v, err := b.Get(encodedID)
	if kv.IsNotFound(err) {
		return nil, ErrAuthNotFound
	}

	if err != nil {
		return nil, ErrInternalServiceError(err)
	}

	return decodeAuthorization(v)
}

func (s *Store) GetAuthorizationByToken(ctx context.Context, tx kv.Tx, token string) (*influxdb.Authorization, error) {
	idx, err := authIndexBucket(tx)
	if err != nil {
		return nil, err
	}

	// use the token to look up the authorization's ID
	idKey, err := idx.Get(authIndexKey(token))
	if IsNotFound(err) {
		return nil, &influxdb.Error{
			Code: influxdb.ENotFound,
			Msg:  "authorization not found",
		}
	}

	var id influxdb.ID
	if err := id.Decode(idKey); err != nil {
		return nil, &influxdb.Error{
			Code: influxdb.EInvalid,
			Err:  err,
		}
	}

	return s.GetAuthorizationByID(ctx, tx, id)
}

// ListAuthorizations returns all the authorizations matching a set of FindOptions. This function is used for
// FindAuthorizationByID, FindAuthorizationByToken, and FindAuthorizations in the AuthorizationService implementation
func (s *Store) ListAuthorizations(ctx context.Context, tx kv.Tx, opt ...influxdb.FindOptions) ([]*influxdb.Authorization, error) {
	if len(opt) == 0 {
		opt = append(opt, influxdb.FindOptions{
			Limit: influxdb.DefaultPageSize,
		})
	}
	o := opt[0]
	if o.Limit > influxdb.MaxPageSize || o.Limit == 0 {
		o.Limit = influxdb.MaxPageSize
	}

	b, err := tx.Bucket(authBucket)
	if err != nil {
		return nil, err
	}

	cursor, err := b.ForwardCursor(nil)
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	count := 0
	auths := []*influxdb.Authorization{}
	for k, v := cursor.Next(); k != nil; k, v = cursor.Next() {
		if o.Offset != 0 && count < o.Offset {
			count++
			continue
		}
		a, err := decodeAuthorization(v)
		if err != nil {
			continue
		}

		auths = append(auths, a)

		if len(auths) >= o.Limit {
			break
		}
	}

	return auths, cursor.Err()
}

func (s *Store) UpdateAuthorization(ctx context.Context, tx kv.Tx, a *influxdb.Authorization) error {
	v, err := encodeAuthorization(a)
	if err != nil {
		return &influxdb.Error{
			Code: influxdb.EInvalid,
			Err:  err,
		}
	}

	encodedID, err := a.ID.Encode()
	if err != nil {
		return &influxdb.Error{
			Code: influxdb.ENotFound,
			Err:  err,
		}
	}

	idx, err := authIndexBucket(tx)
	if err != nil {
		return err
	}

	if err := idx.Put(authIndexKey(a.Token), encodedID); err != nil {
		return &influxdb.Error{
			Code: influxdb.EInternal,
			Err:  err,
		}
	}

	b, err := tx.Bucket(authBucket)
	if err != nil {
		return err
	}

	if err := b.Put(encodedID, v); err != nil {
		return &influxdb.Error{
			Err: err,
		}
	}

	return nil
}

// DeleteAuthorization removes an authorization from storage
func (s *Store) DeleteAuthorization(ctx context.Context, tx kv.Tx, id influxdb.ID) error {
	a, err := s.GetAuthorization(ctx, tx, id)
	if err != nil {
		return nil
	}

	encodedID, err := id.Encode()
	if err != nil {
		return ErrInvalidAuthID
	}

	idx, err := authIndexBucket(tx)
	if err != nil {
		return err
	}

	b, err := tx.Bucket(authBucket)
	if err != nil {
		return err
	}

	if err := idx.Delete([]byte(a.Token)); err != nil {
		return ErrInternalServiceError(err)
	}

	if err := b.Delete(encodedID); err != nil {
		return ErrInternalServiceError(err)
	}

	return nil
}
