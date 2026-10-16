// Package observe turns MRT data into routes as a neighbour announced them. In
// session mode it reads the BGP messages the neighbour sent on the real
// session; in collector mode it reads route-collector RIB dumps and cuts each
// observed path through the neighbour to the part the neighbour itself
// announced, keeping the evidence behind each observation.
package observe
