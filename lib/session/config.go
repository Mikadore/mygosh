package session

import (
	"math"

	"github.com/rotisserie/eris"
)

const (
	defaultInitialWindow       = 256 * 1024
	defaultMaxPacketSize       = 16 * 1024
	defaultWindowAdjustTrigger = 64 * 1024
)

type Config struct {
	InitialWindow         uint32
	MaxPacketSize         uint32
	WindowAdjustThreshold uint32
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
	return nil
}
