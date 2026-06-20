// Package session implements the post-authentication connection multiplexer.
//
// A bound Session owns its framed connection from activation until Done closes.
// The first terminal event determines Wait's result: clean peer EOF is nil;
// local cancellation returns its cause; protocol, transport, and write failures
// return that failure. Cleanup errors are logged and never replace that result.
//
// An accepted Channel exists until its state reaches closed or failed and it is
// removed from the owning Session. Service authorization values are immutable
// decisions only; process and other resource lifetimes are owned by later
// service runtimes rather than this package.
package session
