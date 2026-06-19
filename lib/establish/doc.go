// Package establish composes the role-specific connection setup path:
// handshake, authentication, and construction of a role-agnostic session.
//
// It exists beside lib/session on purpose. lib/session implements the mygosh
// session protocol itself; this package handles the client/server-specific work
// needed to reach that protocol boundary.
package establish
