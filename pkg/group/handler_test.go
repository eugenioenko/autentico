package group

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- HandleCreateGroup ---

func TestHandleCreateGroup_Success(t *testing.T) {
	testutils.WithTestDB(t)

	body, _ := json.Marshal(GroupCreateRequest{Name: "admins", Description: "Admin group"})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/groups", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	HandleCreateGroup(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)
	var resp model.ApiResponse[GroupResponse]
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Equal(t, "admins", resp.Data.Name)
}

func TestHandleCreateGroup_InvalidBody(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/groups", bytes.NewBufferString("not-json"))
	rr := httptest.NewRecorder()
	HandleCreateGroup(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleCreateGroup_EmptyName(t *testing.T) {
	testutils.WithTestDB(t)

	body, _ := json.Marshal(GroupCreateRequest{Name: ""})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/groups", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	HandleCreateGroup(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleCreateGroup_DuplicateName(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestGroup(t, "g1", "admins")

	body, _ := json.Marshal(GroupCreateRequest{Name: "admins"})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/groups", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	HandleCreateGroup(rr, req)
	assert.Equal(t, http.StatusConflict, rr.Code)
}

// --- HandleListGroups ---

func TestHandleListGroups(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroup(t, "g2", "editors")

	req := httptest.NewRequest(http.MethodGet, "/admin/api/groups", nil)
	rr := httptest.NewRecorder()
	HandleListGroups(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]GroupResponse]
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Len(t, resp.Data, 2)
}

// --- HandleGetGroup ---

func TestHandleGetGroup_Success(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestGroup(t, "g1", "admins")

	req := httptest.NewRequest(http.MethodGet, "/admin/api/groups/g1", nil)
	req.SetPathValue("id", "g1")
	rr := httptest.NewRecorder()
	HandleGetGroup(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[GroupResponse]
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Equal(t, "admins", resp.Data.Name)
}

func TestHandleGetGroup_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/groups/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	rr := httptest.NewRecorder()
	HandleGetGroup(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- HandleUpdateGroup ---

func TestHandleUpdateGroup_Success(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestGroup(t, "g1", "admins")

	body, _ := json.Marshal(GroupUpdateRequest{Name: "superadmins"})
	req := httptest.NewRequest(http.MethodPut, "/admin/api/groups/g1", bytes.NewBuffer(body))
	req.SetPathValue("id", "g1")
	rr := httptest.NewRecorder()
	HandleUpdateGroup(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[GroupResponse]
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Equal(t, "superadmins", resp.Data.Name)
}

func TestHandleUpdateGroup_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	body, _ := json.Marshal(GroupUpdateRequest{Name: "x"})
	req := httptest.NewRequest(http.MethodPut, "/admin/api/groups/nonexistent", bytes.NewBuffer(body))
	req.SetPathValue("id", "nonexistent")
	rr := httptest.NewRecorder()
	HandleUpdateGroup(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- HandleDeleteGroup ---

func TestHandleDeleteGroup_Success(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestGroup(t, "g1", "admins")

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/groups/g1", nil)
	req.SetPathValue("id", "g1")
	rr := httptest.NewRecorder()
	HandleDeleteGroup(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleDeleteGroup_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/groups/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	rr := httptest.NewRecorder()
	HandleDeleteGroup(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- HandleListMembers ---

func TestHandleListMembers_Success(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroupMembership(t, "user1", "g1")

	req := httptest.NewRequest(http.MethodGet, "/admin/api/groups/g1/members", nil)
	req.SetPathValue("id", "g1")
	rr := httptest.NewRecorder()
	HandleListMembers(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]GroupMemberResponse]
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Len(t, resp.Data, 1)
}

func TestHandleListMembers_GroupNotFound(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/groups/nonexistent/members", nil)
	req.SetPathValue("id", "nonexistent")
	rr := httptest.NewRecorder()
	HandleListMembers(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- HandleAddMember ---

func TestHandleAddMember_Success(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")

	body, _ := json.Marshal(GroupMemberRequest{UserID: "user1"})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/groups/g1/members", bytes.NewBuffer(body))
	req.SetPathValue("id", "g1")
	rr := httptest.NewRecorder()
	HandleAddMember(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestHandleAddMember_AlreadyMember(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroupMembership(t, "user1", "g1")

	body, _ := json.Marshal(GroupMemberRequest{UserID: "user1"})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/groups/g1/members", bytes.NewBuffer(body))
	req.SetPathValue("id", "g1")
	rr := httptest.NewRecorder()
	HandleAddMember(rr, req)
	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestHandleAddMember_MissingUserID(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestGroup(t, "g1", "admins")

	body, _ := json.Marshal(GroupMemberRequest{UserID: ""})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/groups/g1/members", bytes.NewBuffer(body))
	req.SetPathValue("id", "g1")
	rr := httptest.NewRecorder()
	HandleAddMember(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --- HandleRemoveMember ---

func TestHandleRemoveMember_Success(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroupMembership(t, "user1", "g1")

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/groups/g1/members/user1", nil)
	req.SetPathValue("id", "g1")
	req.SetPathValue("user_id", "user1")
	rr := httptest.NewRecorder()
	HandleRemoveMember(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleRemoveMember_NotAMember(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/groups/g1/members/user1", nil)
	req.SetPathValue("id", "g1")
	req.SetPathValue("user_id", "user1")
	rr := httptest.NewRecorder()
	HandleRemoveMember(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- HandleGetUserGroups ---

func TestHandleGetUserGroups_Success(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroup(t, "g2", "editors")
	testutils.InsertTestGroupMembership(t, "user1", "g1")
	testutils.InsertTestGroupMembership(t, "user1", "g2")

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users/user1/groups", nil)
	req.SetPathValue("id", "user1")
	rr := httptest.NewRecorder()
	HandleGetUserGroups(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]GroupResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 2)
}

func TestHandleGetUserGroups_NoGroups(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users/user1/groups", nil)
	req.SetPathValue("id", "user1")
	rr := httptest.NewRecorder()
	HandleGetUserGroups(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp model.ApiResponse[[]GroupResponse]
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Empty(t, resp.Data)
}
