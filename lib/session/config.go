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
	defaultDisconnectTimeout   = 250 * time.Millisecond
	defaultChannelCloseTimeout = 5 * time.Second

	defaultMaxChannels                         = 64
	defaultMaxPendingOpens                     = 32
	defaultMaxPendingChannelRequests           = 1024
	defaultMaxPendingChannelRequestsPerChannel = 64
	defaultMaxPendingGlobalRequests            = 128
	defaultMaxQueuedFramesPerChannel           = 256
	defaultMaxQueuedFramesTotal                = 8192
	defaultMaxQueuedBytesPerChannel            = 1 << 20
	defaultMaxQueuedBytesTotal                 = 16 << 20
	defaultMaxControlPayload                   = 16 << 10
	defaultMaxTypeLength                       = 128
	defaultMaxCodeLength                       = 64
	defaultMaxMessageLength                    = 1024

	hardMaxChannels                         = 1024
	hardMaxPendingOpens                     = 1024
	hardMaxPendingChannelRequests           = 16 * 1024
	hardMaxPendingChannelRequestsPerChannel = 1024
	hardMaxPendingGlobalRequests            = 2048
	hardMaxQueuedFramesPerChannel           = 4096
	hardMaxQueuedFramesTotal                = 64 * 1024
	hardMaxQueuedBytesPerChannel            = 8 << 20
	hardMaxQueuedBytesTotal                 = 64 << 20
	hardMaxControlPayload                   = 24 << 10
	hardMaxTypeLength                       = 256
	hardMaxCodeLength                       = 128
	hardMaxMessageLength                    = 4096
)

// Limits bounds every peer-controlled collection owned by one Session.
// Zero values select the generous defaults; configured values may tighten but
// never exceed the compiled hard maxima.
type Limits struct {
	MaxChannels                         uint32
	MaxPendingOpens                     uint32
	MaxPendingChannelRequests           uint32
	MaxPendingChannelRequestsPerChannel uint32
	MaxPendingGlobalRequests            uint32
	MaxQueuedFramesPerChannel           uint32
	MaxQueuedFramesTotal                uint32
	MaxQueuedBytesPerChannel            uint64
	MaxQueuedBytesTotal                 uint64
	MaxControlPayload                   uint32
	MaxTypeLength                       uint32
	MaxCodeLength                       uint32
	MaxMessageLength                    uint32
}

func (l Limits) withDefaults() Limits {
	if l.MaxChannels == 0 {
		l.MaxChannels = defaultMaxChannels
	}
	if l.MaxPendingOpens == 0 {
		l.MaxPendingOpens = defaultMaxPendingOpens
	}
	if l.MaxPendingChannelRequests == 0 {
		l.MaxPendingChannelRequests = defaultMaxPendingChannelRequests
	}
	if l.MaxPendingChannelRequestsPerChannel == 0 {
		l.MaxPendingChannelRequestsPerChannel = defaultMaxPendingChannelRequestsPerChannel
	}
	if l.MaxPendingGlobalRequests == 0 {
		l.MaxPendingGlobalRequests = defaultMaxPendingGlobalRequests
	}
	if l.MaxQueuedFramesPerChannel == 0 {
		l.MaxQueuedFramesPerChannel = defaultMaxQueuedFramesPerChannel
	}
	if l.MaxQueuedFramesTotal == 0 {
		l.MaxQueuedFramesTotal = defaultMaxQueuedFramesTotal
	}
	if l.MaxQueuedBytesPerChannel == 0 {
		l.MaxQueuedBytesPerChannel = defaultMaxQueuedBytesPerChannel
	}
	if l.MaxQueuedBytesTotal == 0 {
		l.MaxQueuedBytesTotal = defaultMaxQueuedBytesTotal
	}
	if l.MaxControlPayload == 0 {
		l.MaxControlPayload = defaultMaxControlPayload
	}
	if l.MaxTypeLength == 0 {
		l.MaxTypeLength = defaultMaxTypeLength
	}
	if l.MaxCodeLength == 0 {
		l.MaxCodeLength = defaultMaxCodeLength
	}
	if l.MaxMessageLength == 0 {
		l.MaxMessageLength = defaultMaxMessageLength
	}
	return l
}

func (l Limits) Validate() error {
	l = l.withDefaults()

	check32 := func(name string, value, maximum uint32) error {
		if value == 0 {
			return eris.Errorf("%s must be greater than zero", name)
		}
		if value > maximum {
			return eris.Errorf("%s %d exceeds hard maximum %d", name, value, maximum)
		}
		return nil
	}
	check64 := func(name string, value, maximum uint64) error {
		if value == 0 {
			return eris.Errorf("%s must be greater than zero", name)
		}
		if value > maximum {
			return eris.Errorf("%s %d exceeds hard maximum %d", name, value, maximum)
		}
		return nil
	}

	for _, check := range []struct {
		name       string
		value, max uint32
	}{
		{"max channels", l.MaxChannels, hardMaxChannels},
		{"max pending opens", l.MaxPendingOpens, hardMaxPendingOpens},
		{"max pending channel requests", l.MaxPendingChannelRequests, hardMaxPendingChannelRequests},
		{"max pending channel requests per channel", l.MaxPendingChannelRequestsPerChannel, hardMaxPendingChannelRequestsPerChannel},
		{"max pending global requests", l.MaxPendingGlobalRequests, hardMaxPendingGlobalRequests},
		{"max queued frames per channel", l.MaxQueuedFramesPerChannel, hardMaxQueuedFramesPerChannel},
		{"max queued frames total", l.MaxQueuedFramesTotal, hardMaxQueuedFramesTotal},
		{"max control payload", l.MaxControlPayload, hardMaxControlPayload},
		{"max type length", l.MaxTypeLength, hardMaxTypeLength},
		{"max code length", l.MaxCodeLength, hardMaxCodeLength},
		{"max message length", l.MaxMessageLength, hardMaxMessageLength},
	} {
		if err := check32(check.name, check.value, check.max); err != nil {
			return err
		}
	}
	if err := check64("max queued bytes per channel", l.MaxQueuedBytesPerChannel, hardMaxQueuedBytesPerChannel); err != nil {
		return err
	}
	if err := check64("max queued bytes total", l.MaxQueuedBytesTotal, hardMaxQueuedBytesTotal); err != nil {
		return err
	}
	if l.MaxPendingOpens > l.MaxChannels {
		return eris.New("max pending opens cannot exceed max channels")
	}
	if l.MaxPendingChannelRequestsPerChannel > l.MaxPendingChannelRequests {
		return eris.New("per-channel pending request limit cannot exceed connection limit")
	}
	if l.MaxQueuedFramesPerChannel > l.MaxQueuedFramesTotal {
		return eris.New("per-channel queued frame limit cannot exceed connection limit")
	}
	if l.MaxQueuedBytesPerChannel > l.MaxQueuedBytesTotal {
		return eris.New("per-channel queued byte limit cannot exceed connection limit")
	}
	return nil
}

type Config struct {
	InitialWindow         uint32
	MaxPacketSize         uint32
	WindowAdjustThreshold uint32
	DisconnectTimeout     time.Duration
	ChannelCloseTimeout   time.Duration
	Limits                Limits
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
	if c.DisconnectTimeout == 0 {
		c.DisconnectTimeout = defaultDisconnectTimeout
	}
	if c.ChannelCloseTimeout == 0 {
		c.ChannelCloseTimeout = defaultChannelCloseTimeout
	}
	c.Limits = c.Limits.withDefaults()
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
	if c.MaxPacketSize > hardMaxControlPayload {
		return eris.Errorf("max packet size %d exceeds protocol maximum %d", c.MaxPacketSize, hardMaxControlPayload)
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
	if c.DisconnectTimeout < 0 {
		return eris.New("disconnect timeout must be non-negative")
	}
	if c.ChannelCloseTimeout <= 0 {
		return eris.New("channel close timeout must be greater than zero")
	}
	if err := c.Limits.Validate(); err != nil {
		return eris.Wrap(err, "validate session limits")
	}
	if uint64(c.MaxPacketSize) > c.Limits.MaxQueuedBytesPerChannel {
		return eris.New("max packet size cannot exceed per-channel queued byte limit")
	}
	if uint64(c.MaxPacketSize) > c.Limits.MaxQueuedBytesTotal {
		return eris.New("max packet size cannot exceed total queued byte limit")
	}
	if uint64(c.Limits.MaxControlPayload) > c.Limits.MaxQueuedBytesTotal {
		return eris.New("max control payload cannot exceed total queued byte limit")
	}
	return nil
}
