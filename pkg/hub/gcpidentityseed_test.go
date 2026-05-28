// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !no_sqlite

package hub

import (
	"context"
	"log/slog"
	"testing"

	"github.com/GoogleCloudPlatform/scion/pkg/ent/entc"
	"github.com/GoogleCloudPlatform/scion/pkg/store"
	"github.com/GoogleCloudPlatform/scion/pkg/store/entadapter"
	"github.com/GoogleCloudPlatform/scion/pkg/store/sqlite"
	"github.com/google/uuid"
)

var gcpIdentityGrantScopes = []string{"agent:create", "agent:read", "agent:attach"}

func newGCPIdentityCompositeStore(t *testing.T) *entadapter.CompositeStore {
	t.Helper()
	base, err := sqlite.New(":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	if err := base.Migrate(context.Background()); err != nil {
		t.Fatalf("base migrate: %v", err)
	}
	entClient, err := entc.OpenSQLite("file:" + uuid.NewString() + "?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("ent open: %v", err)
	}
	if err := entc.AutoMigrate(context.Background(), entClient); err != nil {
		t.Fatalf("ent migrate: %v", err)
	}
	cs := entadapter.NewCompositeStore(base, entClient)
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func gcpIdentityForTest(email, projectID string, scopes []string) *ScopedUserIdentity {
	user := NewAuthenticatedUser(GCPIdentityUserID(email), email, gcpIdentitySubjectPrefix+email, gcpIdentityRole, string(ClientTypeAPI))
	return NewScopedUserIdentity(user, projectID, append([]string(nil), scopes...))
}

func gcpIdentityGrantForTest() map[string]GCPIdentityGrant {
	return map[string]GCPIdentityGrant{
		testAllowedSAEmail: {ProjectID: testAllowedProjectID, Scopes: append([]string(nil), gcpIdentityGrantScopes...)},
	}
}

func TestGCPIdentityGrant_AuthorizesInScopeActions(t *testing.T) {
	ctx := context.Background()
	resource := agentResource(&store.Agent{ID: uuid.NewString(), ProjectID: testAllowedProjectID})
	createResource := Resource{Type: "agent", ParentType: "project", ParentID: testAllowedProjectID}

	t.Run("before seed denies", func(t *testing.T) {
		s := newGCPIdentityCompositeStore(t)
		authz := NewAuthzService(s, slog.Default())
		identity := gcpIdentityForTest(testAllowedSAEmail, testAllowedProjectID, gcpIdentityGrantScopes)
		for _, check := range []struct {
			resource Resource
			action   Action
		}{
			{createResource, ActionCreate},
			{resource, ActionRead},
			{resource, ActionAttach},
		} {
			decision := authz.CheckAccess(ctx, identity, check.resource, check.action)
			if decision.Allowed || decision.Reason != "default deny" {
				t.Fatalf("before seed decision for %s = %+v, want default deny", check.action, decision)
			}
		}
	})

	t.Run("after seed allows", func(t *testing.T) {
		s := newGCPIdentityCompositeStore(t)
		if got := seedGCPIdentityGrants(ctx, s, gcpIdentityGrantForTest()); got != 1 {
			t.Fatalf("seeded grants = %d, want 1", got)
		}
		authz := NewAuthzService(s, slog.Default())
		identity := gcpIdentityForTest(testAllowedSAEmail, testAllowedProjectID, gcpIdentityGrantScopes)
		for _, check := range []struct {
			resource Resource
			action   Action
		}{
			{createResource, ActionCreate},
			{resource, ActionRead},
			{resource, ActionAttach},
		} {
			decision := authz.CheckAccess(ctx, identity, check.resource, check.action)
			if !decision.Allowed {
				t.Fatalf("after seed decision for %s = %+v, want allowed", check.action, decision)
			}
		}
	})
}

func TestGCPIdentityGrant_MatchesUATAuthorization(t *testing.T) {
	ctx := context.Background()
	s := newGCPIdentityCompositeStore(t)
	if got := seedGCPIdentityGrants(ctx, s, gcpIdentityGrantForTest()); got != 1 {
		t.Fatalf("seeded grants = %d, want 1", got)
	}

	realUserID := uuid.NewString()
	if err := s.CreateUser(ctx, &store.User{ID: realUserID, Email: "uat-owner@example.com", DisplayName: "UAT Owner", Role: store.UserRoleMember, Status: "active"}); err != nil {
		t.Fatalf("create real user: %v", err)
	}
	if err := s.CreateProject(ctx, &store.Project{ID: testAllowedProjectID, Name: "Test Project", Slug: "test-project", OwnerID: realUserID, Visibility: "private"}); err != nil && err != store.ErrAlreadyExists {
		t.Fatalf("create project: %v", err)
	}
	membersGroup := &store.Group{ID: uuid.NewString(), Name: "Project Members", Slug: "project:test-project:members", GroupType: store.GroupTypeExplicit, ProjectID: testAllowedProjectID}
	if err := s.CreateGroup(ctx, membersGroup); err != nil {
		t.Fatalf("create members group: %v", err)
	}
	if err := s.AddGroupMember(ctx, &store.GroupMember{GroupID: membersGroup.ID, MemberType: store.GroupMemberTypeUser, MemberID: realUserID, Role: store.GroupMemberRoleOwner}); err != nil {
		t.Fatalf("add owner member: %v", err)
	}

	authz := NewAuthzService(s, slog.Default())
	gcpIdentity := gcpIdentityForTest(testAllowedSAEmail, testAllowedProjectID, gcpIdentityGrantScopes)
	uatUser := NewAuthenticatedUser(realUserID, "uat-owner@example.com", "UAT Owner", store.UserRoleMember, string(ClientTypeAPI))
	uatIdentity := NewScopedUserIdentity(uatUser, testAllowedProjectID, gcpIdentityGrantScopes)
	resource := agentResource(&store.Agent{ID: uuid.NewString(), ProjectID: testAllowedProjectID})
	createResource := Resource{Type: "agent", ParentType: "project", ParentID: testAllowedProjectID}

	for _, check := range []struct {
		resource Resource
		action   Action
	}{
		{createResource, ActionCreate},
		{resource, ActionRead},
		{resource, ActionAttach},
	} {
		gcpDecision := authz.CheckAccess(ctx, gcpIdentity, check.resource, check.action)
		uatDecision := authz.CheckAccess(ctx, uatIdentity, check.resource, check.action)
		if gcpDecision.Allowed != uatDecision.Allowed {
			t.Fatalf("decision mismatch for %s: gcp=%+v uat=%+v", check.action, gcpDecision, uatDecision)
		}
	}
}

func TestGCPIdentityGrant_DeniesOutOfScopeAndCrossProject(t *testing.T) {
	ctx := context.Background()
	s := newGCPIdentityCompositeStore(t)
	if got := seedGCPIdentityGrants(ctx, s, gcpIdentityGrantForTest()); got != 1 {
		t.Fatalf("seeded grants = %d, want 1", got)
	}
	authz := NewAuthzService(s, slog.Default())
	identity := gcpIdentityForTest(testAllowedSAEmail, testAllowedProjectID, gcpIdentityGrantScopes)
	resource := agentResource(&store.Agent{ID: uuid.NewString(), ProjectID: testAllowedProjectID})
	if decision := authz.CheckAccess(ctx, identity, resource, ActionDelete); decision.Allowed {
		t.Fatalf("delete decision = %+v, want denied", decision)
	}
	other := agentResource(&store.Agent{ID: uuid.NewString(), ProjectID: uuid.NewString()})
	if decision := authz.CheckAccess(ctx, identity, other, ActionRead); decision.Allowed {
		t.Fatalf("cross-project decision = %+v, want denied", decision)
	}
}

func TestSeedGCPIdentityGrants_Idempotent(t *testing.T) {
	ctx := context.Background()
	s := newGCPIdentityCompositeStore(t)
	if got := seedGCPIdentityGrants(ctx, s, gcpIdentityGrantForTest()); got != 1 {
		t.Fatalf("first seed count = %d, want 1", got)
	}
	if got := seedGCPIdentityGrants(ctx, s, gcpIdentityGrantForTest()); got != 1 {
		t.Fatalf("second seed count = %d, want 1", got)
	}

	uid := GCPIdentityUserID(testAllowedSAEmail)
	if _, err := s.GetUser(ctx, uid); err != nil {
		t.Fatalf("seeded user missing: %v", err)
	}
	group, err := s.GetGroupBySlug(ctx, gcpIdentitySubjectPrefix+testAllowedSAEmail)
	if err != nil {
		t.Fatalf("seeded group missing: %v", err)
	}
	members, err := s.GetGroupMembers(ctx, group.ID)
	if err != nil {
		t.Fatalf("get members: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("members = %d, want 1", len(members))
	}
	policies, err := s.ListPolicies(ctx, store.PolicyFilter{Name: gcpIdentitySubjectPrefix + testAllowedSAEmail + ":agent"}, store.ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if policies.TotalCount != 1 || len(policies.Items) != 1 {
		t.Fatalf("policies = total %d len %d, want 1", policies.TotalCount, len(policies.Items))
	}
	bindings, err := s.GetPolicyBindings(ctx, policies.Items[0].ID)
	if err != nil {
		t.Fatalf("get bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("bindings = %d, want 1", len(bindings))
	}
}

func TestSeedGCPIdentityGrants_NotCalledWhenDisabled(t *testing.T) {
	s := newGCPIdentityCompositeStore(t)
	srv, err := New(ServerConfig{}, s)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	if srv.authConfig.GCPIdentitySvc != nil {
		t.Fatal("GCPIdentitySvc = non-nil, want nil when feature disabled")
	}
	if _, err := s.GetUser(context.Background(), GCPIdentityUserID(testAllowedSAEmail)); err != store.ErrNotFound {
		t.Fatalf("seeded GCP identity user with feature disabled: %v", err)
	}
}
