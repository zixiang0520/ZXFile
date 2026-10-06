package vas

import (
	"crypto/md5"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/gin-gonic/gin"
)

// dependencyFromGin returns the dependency manager from a request context.
func dependencyFromGin(c *gin.Context) dependency.Dep {
	return dependency.FromContext(c)
}

// md5Sum returns the hex-encoded MD5 digest.
func md5Sum(b []byte) string {
	return fmt.Sprintf("%x", md5.Sum(b))
}
