// Package hygiene checks announced routes against registry data other than
// policy: the RPKI origin-validation state of each route and whether a
// matching route object exists. It is pure and reads only through rpsl's
// Source and RPKI types.
package hygiene
