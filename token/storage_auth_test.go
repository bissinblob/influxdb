package token_test

import (
	"context"
	"testing"

	"github.com/influxdata/influxdb/v2"
	"github.com/influxdata/influxdb/v2/inmem"
	"github.com/influxdata/influxdb/v2/kv"
	"github.com/influxdata/influxdb/v2/token"
)

func TestAuth(t *testing.T) {
	s := func() kv.Store {
		return inmem.NewKVStore()
	}

	setup := func(t *testing.T, store *token.Store, tx kv.Tx) {
		for i := 1; i <= 10; i++ {
			err := store.CreateAuth(context.Background(), tx, &influxdb.Authorization{
				ID: influxdb.ID(i),
			})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}
