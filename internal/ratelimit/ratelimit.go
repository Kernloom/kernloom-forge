// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package ratelimit provides a simple in-memory IP-based rate limiter.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter counts requests per IP within a sliding window.
type Limiter struct {
	mu     sync.Mutex
	counts map[string]*bucket
	max    int
	window time.Duration
}

type bucket struct {
	count int
	reset time.Time
}

// New creates a Limiter allowing max requests per window per key.
func New(max int, window time.Duration) *Limiter {
	return &Limiter{counts: make(map[string]*bucket), max: max, window: window}
}

// Allow returns true when the key is within the rate limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.counts[key]
	if !ok || now.After(b.reset) {
		l.counts[key] = &bucket{count: 1, reset: now.Add(l.window)}
		return true
	}
	if b.count >= l.max {
		return false
	}
	b.count++
	return true
}
