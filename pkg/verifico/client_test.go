package verifico

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func workerURL(ts *httptest.Server) string {
	return strings.TrimPrefix(ts.URL, "http://")
}

func TestCompareHashAndPassword_NoWorkers(t *testing.T) {
	Init(Config{})

	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	assert.NoError(t, CompareHashAndPassword(hash, []byte("password")))
	assert.ErrorIs(t, CompareHashAndPassword(hash, []byte("wrong")), bcrypt.ErrMismatchedHashAndPassword)
}

func TestCompareHashAndPassword_WithWorker(t *testing.T) {
	ts := httptest.NewServer(HandleVerify("s3cret"))
	defer ts.Close()

	Init(Config{Enabled: true, Workers: []string{workerURL(ts)}, Secret: "s3cret"})
	defer Init(Config{})

	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	assert.NoError(t, CompareHashAndPassword(hash, []byte("password")))
	assert.ErrorIs(t, CompareHashAndPassword(hash, []byte("wrong")), bcrypt.ErrMismatchedHashAndPassword)
}

func TestCompareHashAndPassword_WorkerDown_Fallback(t *testing.T) {
	Init(Config{Enabled: true, Workers: []string{"127.0.0.1:1"}, Secret: "s3cret"})
	defer Init(Config{})

	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	assert.NoError(t, CompareHashAndPassword(hash, []byte("password")))
}

func TestCompareHashAndPassword_RoundRobin(t *testing.T) {
	var calls [2]int
	ts1 := httptest.NewServer(countingHandler("s3cret", &calls[0]))
	ts2 := httptest.NewServer(countingHandler("s3cret", &calls[1]))
	defer ts1.Close()
	defer ts2.Close()

	Init(Config{Enabled: true, Workers: []string{workerURL(ts1), workerURL(ts2)}, Secret: "s3cret"})
	defer Init(Config{})

	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	for range 4 {
		_ = CompareHashAndPassword(hash, []byte("pw"))
	}

	assert.Equal(t, 2, calls[0])
	assert.Equal(t, 2, calls[1])
}

func TestCompareHashAndPassword_BadSecret_Fallback(t *testing.T) {
	ts := httptest.NewServer(HandleVerify("real-secret"))
	defer ts.Close()

	Init(Config{Enabled: true, Workers: []string{workerURL(ts)}, Secret: "wrong-secret"})
	defer Init(Config{})

	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	assert.NoError(t, CompareHashAndPassword(hash, []byte("password")))
}

func countingHandler(secret string, count *int) http.HandlerFunc {
	h := HandleVerify(secret)
	return func(w http.ResponseWriter, r *http.Request) {
		*count++
		h(w, r)
	}
}
