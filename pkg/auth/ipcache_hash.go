package auth

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

// getIPCacheHash returns a hash of the IP cache map for the given identities.
// this is a super simple serialisation into a long string we then hash and include in the handshake
// the other end executes the same function and compares the hash, only if they match the handshake is successful.
// The most important part is that the order of the IPs and identities is the same on both ends giving us the same
// has in each direction.
func (m *mutualAuthHandler) getIPCacheHash(identities []identity.NumericIdentity) (string, error) {
	// sort identities on numeric value to have the same order on all ends
	sort.Slice(identities, func(i, j int) bool {
		return identities[i] < identities[j]
	})

	bpfIPCacheList := map[string]*ipcache.RemoteEndpointInfo{}
	callback := func(key bpf.MapKey, value bpf.MapValue) {
		bpfIPCacheList[key.String()] = value.(*ipcache.RemoteEndpointInfo)
	}
	if err := ipcache.IPCacheMap().DumpWithCallback(callback); err != nil {
		return "", fmt.Errorf("error dumping contents of map: %s", err)
	}

	m.log.Debug("IP cache map dump: ", bpfIPCacheList)

	mapToHash := make(map[uint32][]string)
	for _, id := range identities {
		mapToHash[id.Uint32()] = []string{}
	}

	for ip, value := range bpfIPCacheList {
		if _, ok := mapToHash[value.SecurityIdentity]; ok {
			m.log.Debugf("Adding IP %s to identity %d", ip, value.SecurityIdentity)
			mapToHash[value.SecurityIdentity] = append(mapToHash[value.SecurityIdentity], ip)
		}
	}

	// sort the IPs to have the same order on all ends
	for id := range mapToHash {
		sort.Strings(mapToHash[id])
	}

	serializedData := ""

	// serialize the map to a string
	for id, ips := range mapToHash {
		serializedData += fmt.Sprintf("%d:%s;", id, ips)
	}

	m.log.Debugf("Serialized data: %s", serializedData)

	// return a sha256 hash of serializedData for comparison
	sum := sha256.Sum256([]byte(serializedData))
	return fmt.Sprintf("%x", sum), nil
}
