package capture_test

import (
	"encoding/binary"
	"testing"
	"time"

	"code.cloudfoundry.org/guardian/dnsaudit/audit"
	"code.cloudfoundry.org/guardian/dnsaudit/capture"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCapture(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Capture Suite")
}

func record(cgroupID, timestamp uint64, packetLen uint32, captureLen uint16, direction uint8, data []byte) []byte {
	raw := make([]byte, capture.RecordLength)
	binary.LittleEndian.PutUint64(raw[0:8], cgroupID)
	binary.LittleEndian.PutUint64(raw[8:16], timestamp)
	binary.LittleEndian.PutUint32(raw[16:20], packetLen)
	binary.LittleEndian.PutUint16(raw[20:22], captureLen)
	raw[22] = direction
	copy(raw[24:], data)
	return raw
}

var _ = Describe("ParseRecord", func() {
	It("parses the record written by the eBPF program", func() {
		r, err := capture.ParseRecord(record(4242, 99, 1500, 3, 1, []byte{1, 2, 3, 4}))
		Expect(err).NotTo(HaveOccurred())
		Expect(r).To(Equal(capture.Record{
			CgroupID:    4242,
			TimestampNs: 99,
			PacketLen:   1500,
			Direction:   audit.Ingress,
			Data:        []byte{1, 2, 3},
		}))
	})

	It("copies the data so the ring buffer can be reused", func() {
		raw := record(1, 1, 1, 2, 0, []byte{7, 8})
		r, err := capture.ParseRecord(raw)
		Expect(err).NotTo(HaveOccurred())
		raw[24] = 0
		Expect(r.Data).To(Equal([]byte{7, 8}))
	})

	It("rejects short records and invalid capture lengths", func() {
		_, err := capture.ParseRecord(make([]byte, 10))
		Expect(err).To(HaveOccurred())
		_, err = capture.ParseRecord(record(1, 1, 1, capture.MaxCaptureLength+1, 0, nil))
		Expect(err).To(HaveOccurred())
		_, err = capture.ParseRecord(record(1, 1, 1, 100, 0, nil)[:50])
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("Clock", func() {
	It("converts monotonic timestamps to wall-clock time", func() {
		wall := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
		monotonic := 5 * time.Second
		clock := capture.NewClock(func() time.Duration { return monotonic }, func() time.Time { return wall })

		Expect(clock.Time(uint64(4 * time.Second)).UTC()).To(Equal(wall.Add(-time.Second)))

		wall = wall.Add(time.Hour)
		monotonic += time.Hour + time.Millisecond
		clock.Resync()
		Expect(clock.Time(uint64(monotonic)).UTC()).To(Equal(wall))
	})
})

var _ = Describe("Record.Event", func() {
	It("builds an audit event", func() {
		clock := capture.NewClock(func() time.Duration { return 0 }, func() time.Time { return time.Unix(100, 0) })
		r := capture.Record{CgroupID: 3, TimestampNs: uint64(time.Second), Direction: audit.Egress, Data: []byte{1}}
		Expect(r.Event(clock)).To(Equal(audit.Event{CgroupID: 3, Time: time.Unix(101, 0), Direction: audit.Egress, Data: []byte{1}}))
	})
})
