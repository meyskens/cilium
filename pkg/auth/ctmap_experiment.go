// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"os"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/sirupsen/logrus"
)

type ctMapAuthenticator struct {
	log logrus.FieldLogger
}

func newCtMapAuthenticator(logger logrus.FieldLogger) *ctMapAuthenticator {
	return &ctMapAuthenticator{
		log: logger,
	}
}

func (r *ctMapAuthenticator) markAuthenticated(req *authRequest) error {
	// crimes beyond this point
	// this is purely a PoC
	// if you see this in production code, run away now please

	// hold on a minute how did we do this in march 2023?
	// simple... we passed the 5tuple to this module via the drop signal
	// now we use the signal map with the authkey, way more efficient
	// but doesn't work for per connection
	// so what the fuck now? well I just enable all auth required to be OK on getting a signal
	// this way we can measure any perfomance loss or issues in this way without
	// the need to completely re-write the signaling handling as well
	// i already broke enough code...

	attempts := 0
	gotcha := false

	for !gotcha {
		if attempts > 10 {
			break
		}
		maps := ctmap.GlobalMaps(true, false)
		r.log.Debugf("dumping %d maps", len(maps))

		for _, m := range maps {
			entries := []ctmap.CtMapRecord{}

			_, err := ctmap.OpenCTMap(m)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}

			}

			callback := func(key bpf.MapKey, value bpf.MapValue) {
				record := ctmap.CtMapRecord{Key: key.(ctmap.CtKey), Value: *value.(*ctmap.CtEntry)}
				entries = append(entries, record)
			}
			if err := m.DumpWithCallback(callback); err != nil {
				r.log.Fatalf("Error while collecting BPF map entries: %s", err)
			}

			r.log.Debugf("checking %d entries", len(entries))
			for _, mpe := range entries {
				entry := mpe.Value
				if (entry.Flags & ctmap.AuthRequired) != 0 {
					entry.Flags = entry.Flags | ctmap.AuthOK

					err := m.Update(mpe.Key, &entry)
					if err != nil {
						r.log.Errorf("failed to update entry: %s", err)
					}
					r.log.Warnf("cleared auth for %s", mpe.Key.String()) // warn is overkill but in a PoC it makes sernse
					gotcha = true

				}
			}

			m.Close()
		}

		attempts++
		if !gotcha { // is this needed, i don't think so, why is this here... i needed it
			r.log.Warnf("no auth found, sleeping")
			time.Sleep(1 * time.Second)
		}
	}

	return nil
}
