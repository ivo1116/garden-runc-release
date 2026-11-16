package users_test

import (
	"code.cloudfoundry.org/guardian/rundmc/users"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeUser", func() {
	DescribeTable("splits a garden user into ids and a name for the runtime",
		func(user string, expectedUID, expectedGID int, expectedName string) {
			execUser, name := users.RuntimeUser(user)
			Expect(execUser.Uid).To(Equal(expectedUID))
			Expect(execUser.Gid).To(Equal(expectedGID))
			Expect(name).To(Equal(expectedName))
		},
		Entry("empty", "", 0, 0, ""),
		Entry("name", "vcap", 0, 0, "vcap"),
		Entry("numeric uid:gid", "1000:1001", 1000, 1001, ""),
		Entry("uid only", "1000", 0, 0, "1000"),
		Entry("name:group", "vcap:vcap", 0, 0, "vcap:vcap"),
		Entry("negative uid", "-1:0", 0, 0, "-1:0"),
	)
})
