package signupinvite

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/email"
	"github.com/eugenioenko/autentico/pkg/middleware"
	_ "github.com/eugenioenko/autentico/pkg/model" // Swagger API envelopes.
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/rs/xid"
)

type CreateRequest struct {
	Kind         string     `json:"kind"`
	Delivery     string     `json:"delivery_method"`
	Email        string     `json:"email"`
	MaxUses      *int       `json:"max_uses"`
	Unlimited    bool       `json:"unlimited"`
	Expires      *time.Time `json:"expires_at"`
	NeverExpires bool       `json:"never_expires"`
}

func (p *CreateRequest) validate(now time.Time) error {
	p.Email = strings.ToLower(strings.TrimSpace(p.Email))
	if p.Email != "" {
		a, err := mail.ParseAddress(p.Email)
		if err != nil || a.Address != p.Email {
			return errors.New("enter a valid email address")
		}
	}
	if p.Delivery != "email" && p.Delivery != "link" {
		return errors.New("choose link or email delivery")
	}
	if p.Delivery == "email" && (p.Email == "" || config.Get().SmtpHost == "") {
		return errors.New("email delivery requires an address and configured SMTP")
	}
	switch p.Kind {
	case "personal":
		if p.Unlimited || p.NeverExpires || (p.MaxUses != nil && *p.MaxUses != 1) {
			return errors.New("personal invitations require one use and an expiration")
		}
		one := 1
		p.MaxUses = &one
	case "shared":
		if p.Email != "" || p.Delivery != "link" || p.Unlimited == (p.MaxUses != nil) || (p.MaxUses != nil && *p.MaxUses < 1) {
			return errors.New("shared links require a positive use limit or explicit unlimited uses, and no email")
		}
	default:
		return errors.New("choose a personal or shared invitation")
	}
	if p.NeverExpires && p.Expires != nil {
		return errors.New("choose an expiration or no expiration")
	}
	if !p.NeverExpires && p.Expires == nil {
		expiry := now.Add(7 * 24 * time.Hour)
		p.Expires = &expiry
	}
	if p.Expires != nil && !p.Expires.After(now) {
		return errors.New("expiration must be in the future")
	}
	return nil
}
func inviteURL(raw string) string {
	bs := config.GetBootstrap()
	return bs.AppURL + bs.AppOAuthPath + "/invite?" + url.Values{"token": {raw}}.Encode()
}
func HandleOpen(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	raw := r.URL.Query().Get("token")
	var id string
	if err := db.GetDB().QueryRow("SELECT id FROM signup_invites WHERE token_hash=? AND "+available, utils.HashToken(raw)).Scan(&id); err != nil {
		view.RenderError(w, r, http.StatusGone, "This invitation is unavailable. Ask an administrator for a new link.")
		return
	}
	http.SetCookie(w, cookie(raw, 1800))
	http.Redirect(w, r, "/account/invite?id="+url.QueryEscape(id), http.StatusSeeOther)
}

type ListResponse struct {
	Items []Invite `json:"items"`
	SMTP  bool     `json:"smtp_available"`
}

// HandleList godoc
// @Summary List signup invitations and email delivery availability
// @Tags signup invites
// @Produce json
// @Success 200 {object} model.ApiResponse[signupinvite.ListResponse]
// @Router /admin/api/signup-invites [get]
func HandleList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.GetDB().Query("SELECT " + columns + " FROM signup_invites ORDER BY created_at DESC,id DESC")
	if err != nil {
		utils.ErrorResponse(w, "Could not list invites", 500)
		return
	}
	defer rows.Close()
	list := ListResponse{Items: []Invite{}, SMTP: config.Get().SmtpHost != ""}
	for rows.Next() {
		i, err := scan(rows)
		if err != nil {
			utils.ErrorResponse(w, "Could not read invite", 500)
			return
		}
		list.Items = append(list.Items, *i)
	}
	if rows.Err() != nil {
		utils.ErrorResponse(w, "Could not list invites", 500)
		return
	}
	utils.SuccessResponse(w, list)
}

type Created struct {
	ID  string `json:"id"`
	URL string `json:"url,omitempty"`
}

// HandleCreate godoc
// @Summary Create a personal or shared signup invite
// @Tags signup invites
// @Accept json
// @Produce json
// @Param request body signupinvite.CreateRequest true "Invitation settings"
// @Success 201 {object} model.ApiResponse[signupinvite.Created]
// @Failure 400 {object} model.ApiError
// @Failure 502 {object} model.ApiError
// @Router /admin/api/signup-invites [post]
func HandleCreate(w http.ResponseWriter, r *http.Request) {
	var p CreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		utils.ErrorResponse(w, "Invalid invitation settings", 400)
		return
	}
	if err := p.validate(time.Now()); err != nil {
		utils.ErrorResponse(w, err.Error(), 400)
		return
	}
	actor := middleware.UserFromContext(r.Context())
	if actor == nil {
		utils.ErrorResponse(w, "Admin required", 403)
		return
	}
	raw, err := authcode.GenerateSecureCode()
	if err != nil {
		utils.ErrorResponse(w, "Could not generate invite", 500)
		return
	}
	id := xid.New().String()
	// SQLite date functions require a canonical timestamp, including its time zone.
	var expires any
	if p.Expires != nil {
		expires = p.Expires.UTC().Format(time.RFC3339Nano)
	}
	_, err = db.GetDB().Exec("INSERT INTO signup_invites(id,token_hash,kind,delivery_method,email,max_uses,expires_at,created_by_user_id) VALUES(?,?,?,?,NULLIF(?,''),?,?,?)", id, utils.HashToken(raw), p.Kind, p.Delivery, p.Email, p.MaxUses, expires, actor.ID)
	if err != nil {
		utils.ErrorResponse(w, "Could not create invite", 500)
		return
	}
	audit.Log("signup_invite_created", actor, "signup_invite", id, nil, utils.GetClientIP(r))
	out := Created{ID: id}
	w.Header().Set("Cache-Control", "no-store")
	if p.Delivery == "link" {
		out.URL = inviteURL(raw)
	} else if err = email.SendSignupInvite(p.Email, inviteURL(raw)); err != nil {
		utils.ErrorResponse(w, "Invitation created. Email delivery failed. Retry from the invitation list.", 502)
		return
	}
	utils.SuccessResponse(w, out, http.StatusCreated)
}

// HandleRetry godoc
// @Summary Rotate and resend a pending email invitation
// @Tags signup invites
// @Param id path string true "Invitation ID"
// @Success 204
// @Failure 409 {object} model.ApiError
// @Router /admin/api/signup-invites/{id}/retry [post]
func HandleRetry(w http.ResponseWriter, r *http.Request) {
	if config.Get().SmtpHost == "" {
		utils.ErrorResponse(w, "Configure SMTP before sending", 400)
		return
	}
	raw, err := authcode.GenerateSecureCode()
	if err != nil {
		utils.ErrorResponse(w, "Could not generate invite", 500)
		return
	}
	id := r.PathValue("id")
	var address string
	err = db.GetWriteDB().QueryRow("UPDATE signup_invites SET token_hash=? WHERE id=? AND delivery_method='email' AND "+available+" RETURNING email", utils.HashToken(raw), id).Scan(&address)
	if errors.Is(err, sql.ErrNoRows) {
		utils.ErrorResponse(w, "Invitation unavailable", 409)
		return
	}
	if err != nil {
		utils.ErrorResponse(w, "Could not rotate invite", 500)
		return
	}
	if err = email.SendSignupInvite(address, inviteURL(raw)); err != nil {
		utils.ErrorResponse(w, "Email delivery failed. Retry from the invitation list.", 502)
		return
	}
	audit.Log("signup_invite_resent", middleware.UserFromContext(r.Context()), "signup_invite", id, nil, utils.GetClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// HandleRevoke godoc
// @Summary Revoke a signup invitation
// @Tags signup invites
// @Param id path string true "Invitation ID"
// @Success 204
// @Failure 404 {object} model.ApiError
// @Router /admin/api/signup-invites/{id} [delete]
func HandleRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := db.GetDB().Exec("UPDATE signup_invites SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND revoked_at IS NULL", id)
	if err != nil {
		utils.ErrorResponse(w, "Could not revoke invite", 500)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		utils.ErrorResponse(w, "Invitation unavailable", 404)
		return
	}
	audit.Log("signup_invite_revoked", middleware.UserFromContext(r.Context()), "signup_invite", id, nil, utils.GetClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}
