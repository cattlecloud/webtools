package nonces

import (
	"errors"
	"sync"

	"github.com/hashicorp/go-set/v3"
	"github.com/shoenig/go-conceal"
)

var (
	ErrTokenNotValid = errors.New("token not valid")
)

type Mint interface {
	Create() *conceal.Text
	Consume(*conceal.Text) error
}

func New() Mint {
	return &mint{
		lock:   new(sync.Mutex),
		active: set.NewHashSet[*conceal.Text](4),
	}
}

type mint struct {
	lock   *sync.Mutex
	active *set.HashSet[*conceal.Text, int]
}

func (m *mint) Create() *conceal.Text {
	token := conceal.UUIDv4()
	m.lock.Lock()
	m.active.Insert(token)
	m.lock.Unlock()
	return token
}

func (m *mint) Consume(proposal *conceal.Text) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if !m.active.Contains(proposal) {
		return ErrTokenNotValid
	}

	m.active.Remove(proposal)
	return nil
}
