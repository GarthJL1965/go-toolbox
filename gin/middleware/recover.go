package middleware

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http/httputil"
	"os"
	"runtime"
	"strings"

	"github.com/gin-gonic/gin"
	"go.imperva.dev/toolbox/gin/context"
)

var (
	dunno     = []byte("???")
	centerDot = []byte("·")
	dot       = []byte(".")
	slash     = []byte("/")
)

// RecoveryHandler is used for recovering from a panic.
//
// This function should output content to the HTTP writer in order to send a response to the caller when a panic
// is encountered.
type RecoveryHandler func(*gin.Context, error, string)

// Recover is a middleware function for recovering from unexpected panics.
//
// Be sure to include the Logger middleware before including this middleware if you wish to log messages using the
// current context's logger rather than the global logger.
func Recover(handler RecoveryHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			logger := context.GetLogger(c)
			if err := recover(); err != nil {
				// check for a broken connection as it does not warrant getting a stack trace
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						if strings.Contains(strings.ToLower(se.Error()), "broken pipe") ||
							strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
							brokenPipe = true
						}
					}
				}
				if brokenPipe {
					logger.Warn().Msgf("broken pipe: connection reset by peer")
					c.Error(err.(error))
					c.Abort()
					return
				}

				// add request headers when debugging making sure to remove any authorization details
				if logger.IsDebugEnabled() {
					httpRequest, _ := httputil.DumpRequest(c.Request, false)
					requestHeaders := strings.Split(string(httpRequest), "\n")
					for i, header := range requestHeaders {
						header := strings.TrimSpace(header)
						current := strings.Split(header, ":")
						if current[0] == "Authorization" {
							requestHeaders[i] = current[0] + ": ********"
						} else {
							requestHeaders[i] = header
						}
					}
					logger = logger.With().Strs("headers", requestHeaders).Logger()
				}

				// log the error information and call the recovery handler function
				stack := stack(3)
				msg := fmt.Sprintf("[Recovery] recovered from unexpected panic: %s\n%s", err.(error).Error(), stack)
				logger.Error().Err(err.(error)).Str("stack", stack).Msg(msg)
				if handler != nil {
					handler(c, err.(error), stack)
				}
			}
		}()
		c.Next()
	}
}

// stack returns a nicely formatted stack frame, skipping skip frames.
func stack(skip int) string {
	buf := new(bytes.Buffer) // the returned data
	// As we loop, we open files and read them. These variables record the currently
	// loaded file.
	var lines [][]byte
	var lastFile string
	for i := skip; ; i++ { // Skip the expected number of frames
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		// Print this much at least.  If we can't find the source, it won't show.
		fmt.Fprintf(buf, "%s:%d (0x%x)\n", file, line, pc)
		if file != lastFile {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				continue
			}
			lines = bytes.Split(data, []byte{'\n'})
			lastFile = file
		}
		fmt.Fprintf(buf, "\t%s: %s\n", function(pc), source(lines, line))
	}
	return buf.String()
}

// source returns a space-trimmed slice of the n'th line.
func source(lines [][]byte, n int) []byte {
	n-- // in stack trace, lines are 1-indexed but our array is 0-indexed
	if n < 0 || n >= len(lines) {
		return dunno
	}
	return bytes.TrimSpace(lines[n])
}

// function returns, if possible, the name of the function containing the PC.
func function(pc uintptr) []byte {
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return dunno
	}
	name := []byte(fn.Name())
	// The name includes the path name to the package, which is unnecessary
	// since the file name is already included.  Plus, it has center dots.
	// That is, we see
	//	runtime/debug.*T·ptrmethod
	// and want
	//	*T.ptrmethod
	// Also the package path might contains dot (e.g. code.google.com/...),
	// so first eliminate the path prefix
	if lastSlash := bytes.LastIndex(name, slash); lastSlash >= 0 {
		name = name[lastSlash+1:]
	}
	if period := bytes.Index(name, dot); period >= 0 {
		name = name[period+1:]
	}
	name = bytes.Replace(name, centerDot, dot, -1)
	return name
}
