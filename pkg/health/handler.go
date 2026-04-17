package health

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

type HealthResponse struct {
	Status   string `json:"status"`
	Database string `json:"database"`
}

// HandleHealth returns the health status of the server.
// @Summary Health check
// @Description Returns the health status of the server and its dependencies. Returns 200 when healthy, 503 when the database is unreachable.
// @Tags health
// @Produce json
// @Success 200 {object} HealthResponse
// @Failure 503 {object} HealthResponse
// @Router /healthz [get]
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	dbStatus := "ok"
	statusCode := http.StatusOK

	if err := db.GetDB().PingContext(r.Context()); err != nil {
		dbStatus = "unavailable"
		statusCode = http.StatusServiceUnavailable
	}

	utils.WriteApiResponse(w, HealthResponse{
		Status:   map[bool]string{true: "ok", false: "degraded"}[statusCode == http.StatusOK],
		Database: dbStatus,
	}, statusCode)
}
