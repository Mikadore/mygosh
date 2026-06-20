package session

import (
	"math"
	"time"

	"github.com/rotisserie/eris"
)

const (
	defaultInitialWindow       = 256 * 1024
	defaultMaxPacketSize       = 16 * 1024
	defaultWindowAdjustTrigger = 64 * 1024
	defaultOutboundQueueDepth  = 32
	defaultHandlerQueueDepth   = 8
	defaultDisconnectTimeout   = 250 * time.Millisecond
)

type Config struct {
	InitialWindow         uint32
	MaxPacketSize         uint32
	WindowAdjustThreshold uint32
	OutboundQueueDepth    int
	HandlerQueueDepth     int
	DisconnectTimeout     time.Duration
}

func (c Config) withDefaults() Config {
	if c.InitialWindow == 0 {
		c.InitialWindow = defaultInitialWindow
	}
	if c.MaxPacketSize == 0 {
		c.MaxPacketSize = defaultMaxPacketSize
	}
	if c.WindowAdjustThreshold == 0 {
		c.WindowAdjustThreshold = defaultWindowAdjustTrigger
	}
	if c.OutboundQueueDepth == 0 {
		c.OutboundQueueDepth = defaultOutboundQueueDepth
	}
	if c.HandlerQueueDepth == 0 {
		c.HandlerQueueDepth = defaultHandlerQueueDepth
	}
	if c.DisconnectTimeout == 0 {
		c.DisconnectTimeout = defaultDisconnectTimeout
	}
	return c
}

func (c Config) Validate() error {
	c = c.withDefaults()

	if c.InitialWindow == 0 {
		return eris.New("initial window must be greater than zero")
	}
	if c.MaxPacketSize == 0 {
		return eris.New("max packet size must be greater than zero")
	}
	if c.MaxPacketSize > c.InitialWindow {
		return eris.Errorf("max packet size %d exceeds initial window %d", c.MaxPacketSize, c.InitialWindow)
	}
	if c.WindowAdjustThreshold == 0 {
		return eris.New("window adjust threshold must be greater than zero")
	}
	if c.WindowAdjustThreshold > c.InitialWindow {
		return eris.Errorf("window adjust threshold %d exceeds initial window %d", c.WindowAdjustThreshold, c.InitialWindow)
	}
	if c.InitialWindow == math.MaxUint32 {
		return eris.New("initial window must be less than max uint32")
	}
	if c.OutboundQueueDepth < 1 {
		return eris.New("outbound queue depth must be greater than zero")
	}
	if c.HandlerQueueDepth < 1 {
		return eris.New("handler queue depth must be greater than zero")
	}
	if c.DisconnectTimeout < 0 {
		return eris.New("disconnect timeout must be non-negative")
	}
	return nil
}
